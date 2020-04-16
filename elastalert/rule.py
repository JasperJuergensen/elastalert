import datetime
import logging
import time
from abc import abstractmethod
from typing import List, Tuple

from croniter import croniter
from elastalert import config
from elastalert.alerter import DebugAlerter
from elastalert.enhancements.drop_match_exception import DropMatchException
from elastalert.exceptions import EAException, EARuntimeException
from elastalert.utils.elastic import get_aggregation_key_value, get_query_key_value
from elastalert.utils.time import (
    dt_to_ts,
    seconds,
    total_seconds,
    ts_now,
    ts_to_dt,
    unix_to_dt,
)
from elastalert.utils.util import elasticsearch_client, lookup_es_key
from elasticsearch import ElasticsearchException

log = logging.getLogger(__name__)


class Rule:
    """"""

    @abstractmethod
    def init_query_factory(self):
        pass

    def __init__(self, rule_config: dict, args=None, es=None):
        """"""
        self.rule_config = rule_config
        self.silence_cache = {}
        self.matches = []
        self.es = es
        self.alerts_sent = 0
        self.query_factory = self.init_query_factory()
        self.cumulative_hits = 0
        self.previous_endtime = None
        if not es:
            self.es = elasticsearch_client(config.CFG().es_client)

    def process_failed_alerts(self):
        # If there are pending aggregate matches, try processing them
        while self.rule_config["agg_matches"]:
            match = self.rule_config["agg_matches"].pop()
            self.add_aggregated_alert(match, self.rule_config)

    def run_rule(
        self, endtime: datetime
    ) -> Tuple[datetime.datetime, datetime.datetime, int, int]:
        """"""
        self.process_failed_alerts()
        run_start = time.time()

        query = self.query_factory.get_query_instance()
        starttime, endtime, self.cumulative_hits = query.run(endtime)

        num_matches = len(self.matches)
        if not self.is_silenced(self.rule_config["name"] + "._silence"):
            self.process_matches()

        # Mark this endtime for next run's start
        self.previous_endtime = endtime

        time_taken = time.time() - run_start
        # Write to ES that we've run this rule against this time period
        body = {
            "rule_name": self.rule_config["name"],
            "endtime": endtime,
            "starttime": starttime,
            "matches": num_matches,
            "hits": self.cumulative_hits,
            "@timestamp": ts_now(),
            "time_taken": time_taken,
        }
        self.writeback("elastalert_status", body)
        alerts_sent = self.alerts_sent
        self.alerts_sent = 0
        return starttime, endtime, self.cumulative_hits, alerts_sent

    def process_matches(self):

        # Process any new matches
        num_matches = len(self.matches)
        while self.matches:
            match = self.matches.pop(0)
            match["num_hits"] = self.cumulative_hits
            match["num_matches"] = num_matches

            # If realert is set, silence the rule for that duration
            # Silence is cached by query_key, if it exists
            # Default realert time is 0 seconds
            silence_cache_key = self.rule_config["name"]
            query_key_value = get_query_key_value(self.rule_config, match)
            if query_key_value is not None:
                silence_cache_key += "." + query_key_value

            if self.is_silenced(silence_cache_key):
                log.info("Ignoring match for silenced rule %s", silence_cache_key)
                continue

            if self.rule_config["realert"]:
                next_alert, exponent = self.next_alert_time(silence_cache_key, ts_now())
                self.set_realert(silence_cache_key, next_alert, exponent)

            if self.rule_config.get("run_enhancements_first"):
                try:
                    for enhancement in self.rule_config["match_enhancements"]:
                        enhancement.process(match)
                except DropMatchException:
                    continue

            # If no aggregation, alert immediately
            if not self.rule_config["aggregation"]:
                self.send_alert([match])
                continue

            # Add it as an aggregated match
            self.add_aggregated_alert(match, self.rule_config)

    def is_silenced(self, silence_cache_key: str) -> bool:
        if (
            silence_cache_key in self.silence_cache
            and ts_now() < self.silence_cache[silence_cache_key][0]
        ):
            return True
        if config.CFG().debug:
            return False

        query = {
            "query": {"term": {"rule_name": silence_cache_key}},
            "sort": {"until": {"order": "desc"}},
        }
        try:
            res = self.es.search(
                index=self.es.resolve_writeback_index(
                    config.CFG().writeback_index, "silence"
                ),
                body=query,
                ignore_unavailable=True,
            )
        except ElasticsearchException as e:
            raise EARuntimeException(
                "Error while querying for alert silence status: %s" % (e),
                rule=self.rule_config["name"],
                original_exception=e,
            )
        if res["hits"]["hits"]:
            until_ts = res["hits"]["hits"][0]["_source"]["until"]
            exponent = res["hits"]["hits"][0]["_source"].get("exponent", 0)
            if silence_cache_key not in self.silence_cache:
                self.silence_cache[silence_cache_key] = (ts_to_dt(until_ts), exponent)
            else:
                self.silence_cache[silence_cache_key] = (
                    ts_to_dt(until_ts),
                    self.silence_cache[silence_cache_key][1],
                )
            if ts_now() < ts_to_dt(until_ts):
                return True
        return False

    def next_alert_time(
        self, silence_cache_key: str, timestamp: datetime.datetime
    ) -> Tuple[datetime.datetime, int]:
        if silence_cache_key in self.silence_cache:
            last_until, exponent = self.silence_cache[silence_cache_key]
        else:
            # If this isn't cached, this is the first alert or writeback_es is down, normal realert
            return timestamp + self.rule_config["realert"], 0
        if not self.rule_config.get("exponential_realert"):
            return timestamp + self.rule_config["realert"], 0

        diff = seconds(timestamp - last_until)
        # Increase exponent if we've alerted recently
        if diff < seconds(self.rule_config["realert"]) * 2 ** exponent:
            exponent += 1
        else:
            # Continue decreasing exponent the longer it's been since the last alert
            while (
                diff > seconds(self.rule_config["realert"]) * 2 ** exponent
                and exponent > 0
            ):
                diff -= seconds(self.rule_config["realert"]) * 2 ** exponent
                exponent -= 1

        wait = datetime.timedelta(
            seconds=seconds(self.rule_config["realert"]) * 2 ** exponent
        )
        if wait >= self.rule_config["exponential_realert"]:
            return timestamp + self.rule_config["exponential_realert"], exponent - 1
        return timestamp + wait, exponent

    def set_realert(self, silence_cache_key, timestamp, exponent):
        """ Write a silence to Elasticsearch for silence_cache_key until timestamp. """
        body = {
            "exponent": exponent,
            "rule_name": silence_cache_key,
            "@timestamp": ts_now(),
            "until": timestamp,
        }

        self.silence_cache[silence_cache_key] = (timestamp, exponent)
        return self.writeback("silence", body)

    def send_alert(self, matches: List, alert_time=None, retried: bool = False):
        """ Send out an alert.

        :param matches: A list of matches.
        :param retried: Already retried sending alert
        :param alert_time: Time of alert
        """
        if not matches:
            return

        if alert_time is None:
            alert_time = ts_now()

        # Enhancements were already run at match time if
        # run_enhancements_first is set or
        # retried==True, which means this is a retry of a failed alert
        if not (self.rule_config.get("run_enhancements_first") or retried):
            for enhancement in self.rule_config["match_enhancements"]:
                valid_matches = []
                for match in matches:
                    try:
                        enhancement.process(match)
                        valid_matches.append(match)
                    except DropMatchException:
                        pass
                matches = valid_matches
                if not matches:
                    return None

        # Don't send real alerts in debug mode
        if config.CFG().debug:
            alerter = DebugAlerter(self.rule_config)
            alerter.alert(matches)
            return None

        # Run the alerts
        alert_sent = False
        alert_exception = None
        # Alert.pipeline is a single object shared between every alerter
        # This allows alerters to pass objects and data between themselves
        alert_pipeline = {"alert_time": alert_time}
        for alert in self.rule_config["alert"]:
            alert.pipeline = alert_pipeline
            try:
                alert.alert(matches)
            except EAException as e:
                raise EARuntimeException(
                    "Error while running alert %s: %s" % (alert.get_info()["type"], e),
                    rule=self.rule_config["name"],
                    original_exception=e,
                )
            else:
                self.alerts_sent += 1
                alert_sent = True

        # Write the alert(s) to ES
        agg_id = None
        for match in matches:
            alert_body = self.get_alert_body(
                match, self.rule_config, alert_sent, alert_time, alert_exception
            )
            # Set all matches to aggregate together
            if agg_id:
                alert_body["aggregate_id"] = agg_id
            res = self.writeback("elastalert", alert_body, self.rule_config)
            if res and not agg_id:
                agg_id = res["_id"]

    def add_aggregated_alert(self, match, rule):
        """ Save a match as a pending aggregate alert to Elasticsearch. """

        # Optionally include the 'aggregation_key' as a dimension for aggregations
        aggregation_key_value = get_aggregation_key_value(rule, match)

        if not rule["current_aggregate_id"].get(aggregation_key_value) or (
            "aggregate_alert_time" in rule
            and aggregation_key_value in rule["aggregate_alert_time"]
            and rule["aggregate_alert_time"].get(aggregation_key_value)
            < ts_to_dt(lookup_es_key(match, rule["timestamp_field"]))
        ):

            # ElastAlert may have restarted while pending alerts exist
            pending_alert = self.find_pending_aggregate_alert(
                rule, aggregation_key_value
            )
            if pending_alert:
                alert_time = ts_to_dt(pending_alert["_source"]["alert_time"])
                rule["aggregate_alert_time"][aggregation_key_value] = alert_time
                agg_id = pending_alert["_id"]
                rule["current_aggregate_id"] = {aggregation_key_value: agg_id}
                log.info(
                    "Adding alert for %s to aggregation(id: %s, aggregation_key: %s), next alert at %s"
                    % (rule["name"], agg_id, aggregation_key_value, alert_time)
                )
            else:
                # First match, set alert_time
                alert_time = ""
                if isinstance(rule["aggregation"], dict) and rule["aggregation"].get(
                    "schedule"
                ):
                    try:
                        iter = croniter(rule["aggregation"]["schedule"], ts_now())
                        alert_time = unix_to_dt(iter.get_next())
                    except Exception as e:
                        raise EARuntimeException(
                            "Error parsing aggregate send time Cron format %s" % e,
                            rule=rule,
                            original_exception=e,
                        )
                else:
                    if rule.get("aggregate_by_match_time", False):
                        match_time = ts_to_dt(
                            lookup_es_key(match, rule["timestamp_field"])
                        )
                        alert_time = match_time + rule["aggregation"]
                    else:
                        alert_time = ts_now() + rule["aggregation"]

                rule["aggregate_alert_time"][aggregation_key_value] = alert_time
                agg_id = None
                log.info(
                    "New aggregation for %s, aggregation_key: %s. next alert at %s."
                    % (rule["name"], aggregation_key_value, alert_time)
                )
        else:
            # Already pending aggregation, use existing alert_time
            alert_time = rule["aggregate_alert_time"].get(aggregation_key_value)
            agg_id = rule["current_aggregate_id"].get(aggregation_key_value)
            log.info(
                "Adding alert for %s to aggregation(id: %s, aggregation_key: %s), next alert at %s"
                % (rule["name"], agg_id, aggregation_key_value, alert_time)
            )

        alert_body = self.get_alert_body(match, rule, False, alert_time)
        if agg_id:
            alert_body["aggregate_id"] = agg_id
        if aggregation_key_value:
            alert_body["aggregation_key"] = aggregation_key_value
        res = self.writeback("elastalert", alert_body, rule)

        # If new aggregation, save _id
        if res and not agg_id:
            rule["current_aggregate_id"][aggregation_key_value] = res["_id"]

        # Couldn't write the match to ES, save it in memory for now
        if not res:
            rule["agg_matches"].append(match)

        return res

    def find_pending_aggregate_alert(self, rule_config, aggregation_key_value=None):
        query = {
            "filter": {
                "bool": {
                    "must": [
                        {"term": {"rule_name": rule_config["name"]}},
                        {"range": {"alert_time": {"gt": ts_now()}}},
                        {"term": {"alert_sent": "false"}},
                    ],
                    "must_not": [{"exists": {"field": "aggregate_id"}}],
                }
            }
        }
        if aggregation_key_value:
            query["filter"]["bool"]["must"].append(
                {"term": {"aggregation_key": aggregation_key_value}}
            )
        if self.es.is_atleastfive():
            query = {"query": {"bool": query}}
        query["sort"] = {"alert_time": {"order": "desc"}}
        try:
            if self.es.is_atleastsixtwo():
                res = self.es.search(
                    index=config.CFG().writeback_index, body=query, size=1
                )
            else:
                res = self.es.deprecated_search(
                    index=config.CFG().writeback_index,
                    doc_type="elastalert",
                    body=query,
                    size=1,
                )
            if len(res["hits"]["hits"]) == 0:
                return None
        except (KeyError, ElasticsearchException) as e:
            raise EARuntimeException(
                "Error searching for pending aggregated matches",
                rule=rule_config,
                query=query,
                original_exception=e,
            )

        return res["hits"]["hits"][0]

    def get_alert_body(self, match, rule, alert_sent, alert_time, alert_exception=None):
        body = {
            "match_body": match,
            "rule_name": rule["name"],
            "alert_info": rule["alert"][0].get_info() if not config.CFG().debug else {},
            "alert_sent": alert_sent,
            "alert_time": alert_time,
        }

        if rule.get("include_match_in_root"):
            body.update({k: v for k, v in match.items() if not k.startswith("_")})

        if config.CFG().add_metadata_alert:
            body["category"] = rule["category"]
            body["description"] = rule["description"]
            body["owner"] = rule["owner"]
            body["priority"] = rule["priority"]

        match_time = lookup_es_key(match, rule["timestamp_field"])
        if match_time is not None:
            body["match_time"] = match_time

        # TODO record info about multiple alerts

        # If the alert failed to send, record the exception
        if not alert_sent:
            body["alert_exception"] = alert_exception
        return body

    def writeback(self, doc_type, body, rule=None, match_body=None):
        writeback_body = body

        for key in list(writeback_body.keys()):
            # Convert any datetime objects to timestamps
            if isinstance(writeback_body[key], datetime.datetime):
                writeback_body[key] = dt_to_ts(writeback_body[key])

        if config.CFG().debug:
            log.info("Skipping writing to ES: %s" % (writeback_body))
            return None

        if "@timestamp" not in writeback_body:
            writeback_body["@timestamp"] = dt_to_ts(ts_now())

        try:
            index = self.es.resolve_writeback_index(
                config.CFG().writeback_index, doc_type
            )
            return self.es.index(index=index, body=body)
        except ElasticsearchException as e:
            log.exception("Error writing alert info to Elasticsearch: %s" % (e))

    @abstractmethod
    def garbage_collect(self, timestamp):
        """ Gets called periodically to remove old data that is useless beyond given timestamp.
        May also be used to compute things in the absence of new data.

        :param timestamp: A timestamp indicating the rule has been run up to that point.
        """
        pass
