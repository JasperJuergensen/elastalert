import argparse
import datetime
import logging
import os
import random
import signal
import sys
import threading
import time
import timeit
import traceback
from email.mime.text import MIMEText
from smtplib import SMTP, SMTPException
from socket import error
from typing import List

import dateutil.tz
import pytz
from apscheduler.schedulers.background import BackgroundScheduler
from croniter import croniter
from elastalert.config import Config
from elastalert.exceptions import EAConfigException, EARuntimeException
from elastalert.loaders import loader_mapping
from elastalert.utils.elastic import get_aggregation_key_value
from elastalert.utils.time import dt_to_ts, dt_to_unix, pretty_ts, ts_to_dt, unix_to_dt
from elastalert.utils.util import (
    EAException,
    cronite_datetime_to_timestamp,
    elasticsearch_client,
    enhance_filter,
    get_module,
    lookup_es_key,
    parse_deadline,
    parse_duration,
    total_seconds,
    ts_now,
)
from elasticsearch.exceptions import ConnectionError, ElasticsearchException

log = logging.getLogger(__name__)


class ElastAlerter(object):
    """ The main ElastAlert runner. This class holds all state about active rules,
    controls when queries are run, and passes information between rules and alerts.

    :param args: An argparse arguments instance. Should contain debug and start

    :param conf: The configuration dictionary. At the top level, this
    contains global options, and under 'rules', contains all state relating
    to rules and alerts. In each rule in conf['rules'], the RuleType and Alerter
    instances live under 'type' and 'alerts', respectively. The conf dictionary
    should not be passed directly from a configuration file, but must be populated
    by config.py:load_rules instead. """

    thread_data = threading.local()

    def parse_args(self, args):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--config",
            action="store",
            dest="config",
            default="config.yaml",
            help="Global config file (default: config.yaml)",
        )
        parser.add_argument(
            "--debug",
            action="store_true",
            dest="debug",
            help="Suppresses alerts and prints information instead. "
            "Not compatible with `--verbose`",
        )
        parser.add_argument(
            "--rule",
            dest="rule",
            help="Run only a specific rule (by filename, must still be in rules folder)",
        )
        parser.add_argument(
            "--silence",
            dest="silence",
            help="Silence rule for a time period. Must be used with --rule. Usage: "
            "--silence <units>=<number>, eg. --silence hours=2",
        )
        parser.add_argument(
            "--start",
            dest="start",
            help="YYYY-MM-DDTHH:MM:SS Start querying from this timestamp. "
            'Use "NOW" to start from current time. (Default: present)',
        )
        parser.add_argument(
            "--end",
            dest="end",
            help="YYYY-MM-DDTHH:MM:SS Query to this timestamp. (Default: present)",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            dest="verbose",
            help="Increase verbosity without suppressing alerts. "
            "Not compatible with `--debug`",
        )
        parser.add_argument(
            "--patience",
            action="store",
            dest="timeout",
            type=parse_duration,
            default=datetime.timedelta(),
            help="Maximum time to wait for ElasticSearch to become responsive.  Usage: "
            "--patience <units>=<number>. e.g. --patience minutes=5",
        )
        parser.add_argument(
            "--pin_rules",
            action="store_true",
            dest="pin_rules",
            help="Stop ElastAlert from monitoring config file changes",
        )
        parser.add_argument(
            "--es_debug",
            action="store_true",
            dest="es_debug",
            help="Enable verbose logging from Elasticsearch queries",
        )
        parser.add_argument(
            "--es_debug_trace",
            action="store",
            dest="es_debug_trace",
            help="Enable logging from Elasticsearch queries as curl command. Queries will be logged to file. Note that "
            "this will incorrectly display localhost:9200 as the host/port",
        )
        self.args = parser.parse_args(args)

    def __init__(self, args):
        self.parse_args(args)

        try:
            self.conf = Config(self.args).conf
        except EAException as e:
            log.exception("Can't load config: %s", e)
            exit(1)
        # Initialise the rule loader and load each rule configuration
        rules_loader_class = loader_mapping.get(
            self.conf["rules_loader"]
        ) or get_module(self.conf["rules_loader"])
        rules_loader = rules_loader_class(self.conf)
        # Make sure we have all the required globals for the loader
        # Make sure we have all required globals
        if rules_loader.required_globals - frozenset(list(self.conf.keys())):
            raise EAConfigException(
                "Config must contain %s"
                % (
                    ", ".join(
                        rules_loader.required_globals
                        - frozenset(list(self.conf.keys()))
                    ),
                )
            )
        self.rules_loader = rules_loader
        self.rules = self.rules_loader.load(self.conf, self.args)

        log.info("%s rules loaded", len(self.rules))

        self.max_query_size = self.conf["max_query_size"]
        self.scroll_keepalive = self.conf["scroll_keepalive"]
        self.writeback_index = self.conf["writeback_index"]
        self.writeback_alias = self.conf["writeback_alias"]
        self.run_every = self.conf["run_every"]
        self.alert_time_limit = self.conf["alert_time_limit"]
        self.disable_rules_on_error = self.conf["disable_rules_on_error"]
        self.notify_email = self.conf.get("notify_email", [])
        self.from_addr = self.conf.get("from_addr", "ElastAlert")
        self.smtp_host = self.conf.get("smtp_host", "localhost")
        self.max_aggregation = self.conf.get("max_aggregation", 10000)
        self.buffer_time = self.conf["buffer_time"]
        self.rule_hashes = self.rules_loader.get_hashes(self.conf, self.args.rule)
        self.starttime = self.args.start
        self.disabled_rules = {}
        self.replace_dots_in_field_names = self.conf.get(
            "replace_dots_in_field_names", False
        )
        self.thread_data.num_hits = 0
        self.thread_data.num_dupes = 0
        self.scheduler = BackgroundScheduler()
        self.string_multi_field_name = self.conf.get("string_multi_field_name", False)
        self.add_metadata_alert = self.conf.get("add_metadata_alert", False)
        self.show_disabled_rules = self.conf.get("show_disabled_rules", True)

        self.writeback_es = elasticsearch_client(self.conf)
        self.es = elasticsearch_client(self.conf)

        for rule in self.rules.values():
            self.init_rule(rule)

        if self.args.silence:
            self.silence()

    def remove_old_events(self, rule):
        # Anything older than the buffer time we can forget
        now = ts_now()
        remove = []
        buffer_time = rule.get("buffer_time", self.buffer_time)
        if rule.get("query_delay"):
            buffer_time += rule["query_delay"]
        for _id, timestamp in rule["processed_hits"].items():
            if now - timestamp > buffer_time:
                remove.append(_id)
        list(map(rule["processed_hits"].pop, remove))

    def init_rule(self, rule_config, new=True) -> dict:
        """ Copies some necessary non-config state from an exiting rule to a new rule. """
        if not new:
            self.scheduler.remove_job(job_id=rule_config["name"])

        enhance_filter(rule_config)

        if "download_dashboard" in rule_config["filter"]:
            log.warning(
                "The download_dashboard setting for filter is currently not available"
            )
            del rule_config["filter"]["download_dashboard"]

        blank_rule = {
            "agg_matches": [],
            "aggregate_alert_time": {},
            "current_aggregate_id": {},
            "processed_hits": {},
            "run_every": self.run_every,
            "has_run_once": False,
        }
        rule = blank_rule

        # Set rule to either a blank template or existing rule with same name
        if not new:
            rule = self.rules.get(rule_config["name"], blank_rule)

        copy_properties = [
            "agg_matches",
            "current_aggregate_id",
            "aggregate_alert_time",
            "processed_hits",
            "starttime",
            "minimum_starttime",
            "has_run_once",
        ]
        for prop in copy_properties:
            if prop not in rule:
                continue
            rule_config[prop] = rule[prop]

        job = self.scheduler.add_job(
            self.handle_rule_execution,
            "interval",
            args=[rule_config],
            seconds=rule_config["run_every"].total_seconds(),
            id=rule_config["name"],
            max_instances=1,
            jitter=5,
        )
        job.modify(
            next_run_time=datetime.datetime.now()
            + datetime.timedelta(seconds=random.randint(0, 15))
        )

        return rule_config

    def start(self):
        """ Periodically go through each rule and run it """
        if self.starttime:
            if self.starttime == "NOW":
                self.starttime = ts_now()
            else:
                try:
                    self.starttime = ts_to_dt(self.starttime)
                except (TypeError, ValueError):
                    self.handle_error(
                        "%s is not a valid ISO8601 timestamp (YYYY-MM-DDTHH:MM:SS+XX:00)"
                        % (self.starttime)
                    )
                    exit(1)

        for rule in self.rules.values():
            rule["initial_starttime"] = self.starttime
        self.wait_until_responsive(timeout=self.args.timeout)
        self.running = True
        log.info("Starting up")
        self.scheduler.add_job(
            self.handle_pending_alerts,
            "interval",
            seconds=self.run_every.total_seconds(),
            id="_internal_handle_pending_alerts",
        )
        if not self.args.pin_rules:
            self.scheduler.add_job(
                self.handle_config_change,
                "interval",
                seconds=self.run_every.total_seconds(),
                id="_internal_handle_config_change",
            )
        self.scheduler.start()
        while self.running:
            next_run = datetime.datetime.utcnow() + self.run_every

            # Quit after end_time has been reached
            if self.args.end:
                endtime = ts_to_dt(self.args.end)

                if next_run.replace(tzinfo=dateutil.tz.tzutc()) > endtime:
                    exit(0)

            if next_run < datetime.datetime.utcnow():
                continue

            # Show disabled rules
            if self.show_disabled_rules:
                log.info("Disabled rules are: %s" % (str(self.get_disabled_rules())))

            # Wait before querying again
            sleep_duration = total_seconds(next_run - datetime.datetime.utcnow())
            self.sleep_for(sleep_duration)

    def wait_until_responsive(self, timeout, clock=timeit.default_timer):
        """Wait until ElasticSearch becomes responsive (or too much time passes)."""

        # Elapsed time is a floating point number of seconds.
        timeout = timeout.total_seconds()

        # Don't poll unless we're asked to.
        if timeout <= 0.0:
            return

        # Periodically poll ElasticSearch.  Keep going until ElasticSearch is
        # responsive *and* the writeback index exists.
        ref = clock()
        while (clock() - ref) < timeout:
            try:
                if self.writeback_es.indices.exists(self.writeback_alias):
                    return
            except ConnectionError:
                pass
            time.sleep(1.0)

        if self.writeback_es.ping():
            log.error(
                'Writeback alias "%s" does not exist, did you run `elastalert-create-index`?',
                self.writeback_alias,
            )
        else:
            log.error(
                'Could not reach ElasticSearch at "%s:%d".',
                self.conf["es_host"],
                self.conf["es_port"],
            )
        exit(1)

    def handle_pending_alerts(self):
        self.thread_data.alerts_sent = 0
        self.send_pending_alerts()
        log.info(
            "Background alerts thread %s pending alerts sent at %s"
            % (self.thread_data.alerts_sent, pretty_ts(ts_now()))
        )

    def handle_config_change(self):
        new_rule_hashes = self.rules_loader.get_hashes(self.conf, self.args.rule)

        # Check each current rule for changes
        for rule_name, hash_value in self.rule_hashes.items():
            if rule_name not in new_rule_hashes:
                # Rule file was deleted
                log.info("Rule %s not found, stopping rule execution", rule_name)
                rule = self.rules[rule_name]
                self.scheduler.remove_job(job_id=rule["name"])
                del self.rules[rule_name]
                continue
            if hash_value != new_rule_hashes[rule_name]:
                # Rule file was changed, reload rule
                try:
                    new_rule = self.rules_loader.get_rule_config(rule_name, self.conf)
                    if "is_enabled" in new_rule and not new_rule["is_enabled"]:
                        log.info("Rule file %s is now disabled.", rule_name)
                        # Remove this rule if it's been disabled
                        del self.rules[rule_name]
                        continue
                except EAException as e:
                    message = "Could not load rule %s: %s" % (rule_name, e)
                    self.handle_error(message)
                    self.send_notification_email(exception=e)
                    continue
                log.info("Reloading configuration for rule %s", rule_name)

                # Re-enable if rule had been disabled
                if new_rule["name"] in self.disabled_rules:
                    self.rules[new_rule["name"]] = self.disabled_rules[new_rule["name"]]
                    del self.disabled_rules[new_rule["name"]]

                # Initialize the rule that matches rule_name
                self.rules[rule_name] = self.init_rule(new_rule, False)

        # Load new rules
        if not self.args.rule:
            for rule_name in set(new_rule_hashes.keys()) - set(self.rule_hashes.keys()):
                try:
                    new_rule = self.rules_loader.get_rule_config(rule_name, self.conf)
                    if "is_enabled" in new_rule and not new_rule["is_enabled"]:
                        continue
                    if new_rule["name"] in self.rules:
                        raise EAException(
                            "A rule with the name %s already exists"
                            % (new_rule["name"])
                        )
                except EAException as e:
                    self.handle_error("Could not load rule %s: %s" % (rule_name, e))
                    self.send_notification_email(exception=e, rule_file=rule_name)
                    continue
                if self.init_rule(new_rule):
                    log.info("Loaded new rule %s" % (rule_name))
                    self.rules[new_rule["name"]] = new_rule

        self.rule_hashes = new_rule_hashes
        log.info("Background configuration change check run at %s", pretty_ts(ts_now()))

    def handle_rule_execution(self, rule_config):
        self.thread_data.alerts_sent = 0
        next_run = datetime.datetime.utcnow() + rule_config["run_every"]
        # Set endtime based on the rule's delay
        delay = rule_config.get("query_delay")
        if hasattr(self.args, "end") and self.args.end:
            endtime = ts_to_dt(self.args.end)
        elif delay:
            endtime = ts_now() - delay
        else:
            endtime = ts_now()

        # Apply rules based on execution time limits
        if rule_config.get("limit_execution"):
            rule_config["next_starttime"] = None
            rule_config["next_min_starttime"] = None
            exec_next = next(croniter(rule_config["limit_execution"]))
            endtime_epoch = dt_to_unix(endtime)
            # If the estimated next endtime (end + run_every) isn't at least a minute past the next exec time
            # That means that we need to pause execution after this run
            if (
                endtime_epoch + rule_config["run_every"].total_seconds()
                < exec_next - 59
            ):
                # apscheduler requires pytz tzinfos, so don't use unix_to_dt here!
                rule_config["next_starttime"] = datetime.datetime.utcfromtimestamp(
                    exec_next
                ).replace(tzinfo=pytz.utc)
                if rule_config.get("limit_execution_coverage"):
                    rule_config["next_min_starttime"] = rule_config["next_starttime"]
                if not rule_config["has_run_once"]:
                    self.reset_rule_schedule(rule_config)
                    return

        rule_config["has_run_once"] = True
        try:
            num_matches = rule_config["type"].run_rule(
                endtime, rule_config.get("initial_starttime")
            )
        except EARuntimeException as e:
            self.handle_error(
                "Error running rule %s: %s" % (rule_config["name"], e.msg),
                {"rule": rule_config["name"]},
            )
        except Exception as e:
            self.handle_uncaught_exception(e, rule_config)
        else:
            old_starttime = pretty_ts(
                rule_config.get("original_starttime"), rule_config.get("use_local_time")
            )
            log.info(
                "Ran %s from %s to %s: %s matches," " %s alerts sent",
                rule_config["name"],
                old_starttime,
                pretty_ts(endtime, rule_config.get("use_local_time")),
                num_matches,
                self.thread_data.alerts_sent,
            )
            self.thread_data.alerts_sent = 0

            if next_run < datetime.datetime.utcnow():
                # We were processing for longer than our refresh interval
                # This can happen if --start was specified with a large time period
                # or if we are running too slow to process events in real time.
                log.warning(
                    "Querying from %s to %s took longer than %s!"
                    % (
                        old_starttime,
                        pretty_ts(endtime, rule_config.get("use_local_time")),
                        self.run_every,
                    )
                )

        rule_config["initial_starttime"] = None

        self.remove_old_events(rule_config)

        self.reset_rule_schedule(rule_config)

    def reset_rule_schedule(self, rule):
        # We hit the end of a execution schedule, pause ourselves until next run
        if rule.get("limit_execution") and rule["next_starttime"]:
            self.scheduler.modify_job(
                job_id=rule["name"], next_run_time=rule["next_starttime"]
            )
            # If we are preventing covering non-scheduled time periods, reset min_starttime and previous_endtime
            if rule["next_min_starttime"]:
                rule["minimum_starttime"] = rule["next_min_starttime"]
                rule["previous_endtime"] = rule["next_min_starttime"]
            log.info(
                "Pausing %s until next run at %s"
                % (rule["name"], pretty_ts(rule["next_starttime"]))
            )

    def stop(self):
        """ Stop an ElastAlert runner that's been started """
        self.running = False

    def get_disabled_rules(self) -> List[str]:
        """ Return disabled rules """
        return list(self.disabled_rules.keys())

    def sleep_for(self, duration):
        """ Sleep for a set duration """
        log.info("Sleeping for %s seconds" % (duration))
        time.sleep(duration)

    def get_alert_body(self, match, rule, alert_sent, alert_time, alert_exception=None):
        body = {
            "match_body": match,
            "rule_name": rule["name"],
            "alert_info": rule["alert"][0].get_info() if not self.conf["debug"] else {},
            "alert_sent": alert_sent,
            "alert_time": alert_time,
        }

        if rule.get("include_match_in_root"):
            body.update({k: v for k, v in match.items() if not k.startswith("_")})

        if self.add_metadata_alert:
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

        if self.conf["debug"]:
            log.info("Skipping writing to ES: %s" % (writeback_body))
            return None

        if "@timestamp" not in writeback_body:
            writeback_body["@timestamp"] = dt_to_ts(ts_now())

        try:
            index = self.writeback_es.resolve_writeback_index(
                self.writeback_index, doc_type
            )
            if self.writeback_es.is_atleastsixtwo():
                res = self.writeback_es.index(index=index, body=body)
            else:
                res = self.writeback_es.index(index=index, doc_type=doc_type, body=body)
            return res
        except ElasticsearchException as e:
            log.exception("Error writing alert info to Elasticsearch: %s" % (e))

    def find_recent_pending_alerts(self, time_limit):
        """ Queries writeback_es to find alerts that did not send
        and are newer than time_limit """

        # XXX only fetches 1000 results. If limit is reached, next loop will catch them
        # unless there is constantly more than 1000 alerts to send.

        # Fetch recent, unsent alerts that aren't part of an aggregate, earlier alerts first.
        inner_query = {
            "query_string": {"query": "!_exists_:aggregate_id AND alert_sent:false"}
        }
        time_filter = {
            "range": {
                "alert_time": {
                    "from": dt_to_ts(ts_now() - time_limit),
                    "to": dt_to_ts(ts_now()),
                }
            }
        }
        sort = {"sort": {"alert_time": {"order": "asc"}}}
        if self.writeback_es.is_atleastfive():
            query = {"query": {"bool": {"must": inner_query, "filter": time_filter}}}
        else:
            query = {"query": inner_query, "filter": time_filter}
        query.update(sort)
        try:
            if self.writeback_es.is_atleastsixtwo():
                res = self.writeback_es.search(
                    index=self.writeback_index, body=query, size=1000
                )
            else:
                res = self.writeback_es.deprecated_search(
                    index=self.writeback_index,
                    doc_type="elastalert",
                    body=query,
                    size=1000,
                )
            if res["hits"]["hits"]:
                return res["hits"]["hits"]
        except ElasticsearchException as e:
            log.exception("Error finding recent pending alerts: %s %s", e, query)
        return []

    def alert(
        self, matches: List, rule_config: dict, alert_time, retried: bool = False
    ):
        rule_config["type"].send_alert(matches, alert_time, retried)

    def send_pending_alerts(self):
        pending_alerts = self.find_recent_pending_alerts(self.alert_time_limit)
        for alert in pending_alerts:
            _id = alert["_id"]
            alert = alert["_source"]
            try:
                rule_name = alert.pop("rule_name")
                alert_time = alert.pop("alert_time")
                match_body = alert.pop("match_body")
            except KeyError:
                # Malformed alert, drop it
                continue

            # Find original rule
            rule = self.rules.get(rule_name)
            if not rule:
                # Original rule is missing, keep alert for later if rule reappears
                continue

            # Set current_es for top_count_keys query
            self.thread_data.current_es = elasticsearch_client(rule)

            # Send the alert unless it's a future alert
            if ts_now() > ts_to_dt(alert_time):
                aggregated_matches = self.get_aggregated_matches(_id)
                if aggregated_matches:
                    matches = [match_body] + [
                        agg_match["match_body"] for agg_match in aggregated_matches
                    ]
                    self.alert(matches, rule, alert_time=alert_time)
                else:
                    # If this rule isn't using aggregation, this must be a retry of a failed alert
                    retried = False
                    if not rule.get("aggregation"):
                        retried = True
                    self.alert(
                        [match_body], rule, alert_time=alert_time, retried=retried
                    )

                if rule["current_aggregate_id"]:
                    for qk, agg_id in rule["current_aggregate_id"].items():
                        if agg_id == _id:
                            rule["current_aggregate_id"].pop(qk)
                            break

                # Delete it from the index
                try:
                    if self.writeback_es.is_atleastsixtwo():
                        self.writeback_es.delete(index=self.writeback_index, id=_id)
                    else:
                        self.writeback_es.delete(
                            index=self.writeback_index, doc_type="elastalert", id=_id
                        )
                except ElasticsearchException:  # TODO: Give this a more relevant exception, try:except: is evil.
                    self.handle_error(
                        "Failed to delete alert %s at %s" % (_id, alert_time)
                    )

        # Send in memory aggregated alerts
        for rule in self.rules.values():
            if rule["agg_matches"]:
                for aggregation_key_value, aggregate_alert_time in rule[
                    "aggregate_alert_time"
                ].items():
                    if ts_now() > aggregate_alert_time:
                        alertable_matches = [
                            agg_match
                            for agg_match in rule["agg_matches"]
                            if get_aggregation_key_value(rule, agg_match)
                            == aggregation_key_value
                        ]
                        self.alert(alertable_matches, rule)
                        rule["agg_matches"] = [
                            agg_match
                            for agg_match in rule["agg_matches"]
                            if get_aggregation_key_value(rule, agg_match)
                            != aggregation_key_value
                        ]

    def get_aggregated_matches(self, _id):
        """ Removes and returns all matches from writeback_es that have aggregate_id == _id """

        # XXX if there are more than self.max_aggregation matches, you have big alerts and we will leave entries in ES.
        query = {
            "query": {"query_string": {"query": "aggregate_id:'%s'" % (_id)}},
            "sort": {"@timestamp": "asc"},
        }
        matches = []
        try:
            if self.writeback_es.is_atleastsixtwo():
                res = self.writeback_es.search(
                    index=self.writeback_index, body=query, size=self.max_aggregation
                )
            else:
                res = self.writeback_es.deprecated_search(
                    index=self.writeback_index,
                    doc_type="elastalert",
                    body=query,
                    size=self.max_aggregation,
                )
            for match in res["hits"]["hits"]:
                matches.append(match["_source"])
                if self.writeback_es.is_atleastsixtwo():
                    self.writeback_es.delete(
                        index=self.writeback_index, id=match["_id"]
                    )
                else:
                    self.writeback_es.delete(
                        index=self.writeback_index,
                        doc_type="elastalert",
                        id=match["_id"],
                    )
        except (KeyError, ElasticsearchException) as e:
            self.handle_error(
                "Error fetching aggregated matches: %s" % (e), {"id": _id}
            )
        return matches

    def find_pending_aggregate_alert(self, rule, aggregation_key_value=None):
        query = {
            "filter": {
                "bool": {
                    "must": [
                        {"term": {"rule_name": rule["name"]}},
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
        if self.writeback_es.is_atleastfive():
            query = {"query": {"bool": query}}
        query["sort"] = {"alert_time": {"order": "desc"}}
        try:
            if self.writeback_es.is_atleastsixtwo():
                res = self.writeback_es.search(
                    index=self.writeback_index, body=query, size=1
                )
            else:
                res = self.writeback_es.deprecated_search(
                    index=self.writeback_index,
                    doc_type="elastalert",
                    body=query,
                    size=1,
                )
            if len(res["hits"]["hits"]) == 0:
                return None
        except (KeyError, ElasticsearchException) as e:
            self.handle_error(
                "Error searching for pending aggregated matches: %s" % (e),
                {"rule_name": rule["name"]},
            )
            return None

        return res["hits"]["hits"][0]

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
                    croniter._datetime_to_timestamp = (
                        cronite_datetime_to_timestamp  # For Python 2.6 compatibility
                    )
                    try:
                        iter = croniter(rule["aggregation"]["schedule"], ts_now())
                        alert_time = unix_to_dt(iter.get_next())
                    except Exception as e:
                        self.handle_error(
                            "Error parsing aggregate send time Cron format %s" % (e),
                            rule["aggregation"]["schedule"],
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

    def silence(self, silence_cache_key=None):
        """ Silence an alert for a period of time. --silence and --rule must be passed as args. """
        if self.conf["debug"]:
            log.error("--silence not compatible with --debug")
            exit(1)

        if not self.args.rule:
            log.error("--silence must be used with --rule")
            exit(1)

        # With --rule, self.rules will only contain that specific rule
        if not silence_cache_key:
            silence_cache_key = self.rules.values()[0]["name"] + "._silence"

        try:
            silence_ts = parse_deadline(self.args.silence)
        except (ValueError, TypeError):
            log.error("%s is not a valid time period" % (self.args.silence))
            exit(1)

        if not self.rules.values()[0]["type"].set_realert(
            silence_cache_key, silence_ts, 0
        ):
            log.error("Failed to save silence command to Elasticsearch")
            exit(1)

        log.info(
            "Success. %s will be silenced until %s" % (silence_cache_key, silence_ts)
        )

    def handle_error(self, message, data=None):
        """ Logs message at error level and writes message, data and traceback to Elasticsearch. """
        log.error(message)
        body = {"message": message}
        tb = traceback.format_exc()
        body["traceback"] = tb.strip().split("\n")
        if data:
            body["data"] = data
        self.writeback("elastalert_error", body)

    def handle_uncaught_exception(self, exception, rule):
        """ Disables a rule and sends a notification. """
        log.error(traceback.format_exc())
        self.handle_error(
            "Uncaught exception running rule %s: %s" % (rule["name"], exception),
            {"rule": rule["name"]},
        )
        if self.disable_rules_on_error:
            del self.rules[rule["name"]]
            self.disabled_rules[rule["name"]] = rule
            self.scheduler.pause_job(job_id=rule["name"])
            log.info("Rule %s disabled", rule["name"])
        if self.notify_email:
            self.send_notification_email(exception=exception, rule=rule)

    def send_notification_email(
        self, text="", exception=None, rule=None, subject=None, rule_file=None
    ):
        email_body = text
        rule_name = None
        if rule:
            rule_name = rule["name"]
        elif rule_file:
            rule_name = rule_file
        if exception and rule_name:
            if not subject:
                subject = "Uncaught exception in ElastAlert - %s" % (rule_name)
            email_body += "\n\n"
            email_body += "The rule %s has raised an uncaught exception.\n\n" % (
                rule_name
            )
            if self.disable_rules_on_error:
                modified = (
                    " or if the rule config file has been modified"
                    if not self.args.pin_rules
                    else ""
                )
                email_body += (
                    "It has been disabled and will be re-enabled when ElastAlert restarts%s.\n\n"
                    % (modified)
                )
            tb = traceback.format_exc()
            email_body += tb

        if isinstance(self.notify_email, str):
            self.notify_email = [self.notify_email]
        email = MIMEText(email_body)
        email["Subject"] = subject if subject else "ElastAlert notification"
        recipients = self.notify_email
        if rule and rule.get("notify_email"):
            if isinstance(rule["notify_email"], str):
                rule["notify_email"] = [rule["notify_email"]]
            recipients = recipients + rule["notify_email"]
        recipients = list(set(recipients))
        email["To"] = ", ".join(recipients)
        email["From"] = self.from_addr
        email["Reply-To"] = self.conf.get("email_reply_to", email["To"])

        try:
            smtp = SMTP(self.smtp_host)
            smtp.sendmail(self.from_addr, recipients, email.as_string())
        except (SMTPException, error) as e:
            self.handle_error(
                "Error connecting to SMTP host: %s" % (e), {"email_body": email_body}
            )


def handle_signal(signal, frame):
    log.info("SIGINT received, stopping ElastAlert...")
    # use os._exit to exit immediately and avoid someone catching SystemExit
    os._exit(0)


def main(args=None):
    signal.signal(signal.SIGINT, handle_signal)
    if not args:
        args = sys.argv[1:]
    client = ElastAlerter(args)
    if not client.args.silence:
        client.start()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
