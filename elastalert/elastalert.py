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
from dataclasses import asdict
from email.mime.text import MIMEText
from smtplib import SMTP, SMTPException
from socket import error
from typing import List

import dateutil.tz
import pytz
from apscheduler.schedulers.background import BackgroundScheduler
from croniter import croniter
from elastalert import config
from elastalert.exceptions import EAConfigException, EARuntimeException
from elastalert.loaders import loader_mapping
from elastalert.utils.elastic import get_aggregation_key_value
from elastalert.utils.time import dt_to_ts, dt_to_unix, pretty_ts, ts_to_dt
from elastalert.utils.util import (
    EAException,
    elasticsearch_client,
    enhance_filter,
    get_module,
    parse_deadline,
    total_seconds,
    ts_now,
)
from elasticsearch.exceptions import ConnectionError, ElasticsearchException

log = logging.getLogger("elastalert")


class ElastAlerter(object):
    """ The main ElastAlert runner. This class holds all state about active rules,
    controls when queries are run, and passes information between rules and alerts.

    :param args: An argparse arguments instance. Should contain debug and start
 """

    thread_data = threading.local()

    def __init__(self, args):
        try:
            config.load_config(args)
        except EAException as e:
            log.exception("Can't load config: %s", e)
            exit(1)
        # Initialise the rule loader and load each rule configuration
        rules_loader_class = loader_mapping.get(
            config.CFG().rules_loader
        ) or get_module(config.CFG().rules_loader)
        rules_loader = rules_loader_class(config.CFG())
        # Make sure we have all the required globals for the loader
        # Make sure we have all required globals
        if (
            len(
                rules_loader.required_globals
                - frozenset(list(asdict(config.CFG()).keys()))
            )
            != 0
        ):
            raise EAConfigException(
                "Config must contain %s"
                % (
                    ", ".join(
                        rules_loader.required_globals
                        - frozenset(list(asdict(config.CFG()).keys()))
                    ),
                )
            )
        self.rules_loader = rules_loader
        self.rules = self.rules_loader.load(config.CFG().args)

        log.info("%s rules loaded", len(self.rules))

        self.rule_hashes = self.rules_loader.get_hashes(config.CFG().args.rule)
        self.starttime = config.CFG().args.start
        self.disabled_rules = {}
        self.replace_dots_in_field_names = config.CFG().replace_dots_in_field_names
        self.thread_data.num_hits = 0
        self.thread_data.num_dupes = 0
        self.scheduler = BackgroundScheduler()
        self.string_multi_field_name = config.CFG().string_multi_field_name
        self.add_metadata_alert = config.CFG().add_metadata_alert
        self.show_disabled_rules = config.CFG().show_disabled_rules
        self.running = False

        self.writeback_es = elasticsearch_client(config.CFG().es_client)

        for rule in self.rules.values():
            self.init_rule(rule)

        if config.CFG().args.silence:
            self.silence()

    def remove_old_events(self, rule):
        # Anything older than the buffer time we can forget
        now = ts_now()
        buffer_time = rule.get("buffer_time", config.CFG().buffer_time)
        if rule.get("query_delay"):
            buffer_time += rule["query_delay"]
        remove = [
            _id
            for _id, timestamp in rule["processed_hits"].items()
            if now - timestamp > buffer_time
        ]

        list(map(rule["processed_hits"].pop, remove))

    def init_rule(self, rule_config: dict, new=True, rule_name: str = None) -> dict:
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
            "run_every": config.CFG().run_every,
            "has_run_once": False,
        }
        rule = blank_rule

        # Set rule to either a blank template or existing rule with same name
        if not new:
            rule = self.rules.get(rule_name, blank_rule)

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
                        % self.starttime
                    )
                    exit(1)

        for rule in self.rules.values():
            rule["initial_starttime"] = self.starttime
        self.wait_until_responsive(timeout=config.CFG().args.timeout)
        self.running = True
        log.info("Starting up")
        self.scheduler.add_job(
            self.handle_pending_alerts,
            "interval",
            seconds=config.CFG().run_every.total_seconds(),
            id="_internal_handle_pending_alerts",
        )
        if not config.CFG().args.pin_rules:
            self.scheduler.add_job(
                self.handle_config_change,
                "interval",
                seconds=config.CFG().run_every.total_seconds(),
                id="_internal_handle_config_change",
            )
        self.scheduler.start()
        while self.running:
            next_run = datetime.datetime.utcnow() + config.CFG().run_every

            # Quit after end_time has been reached
            if config.CFG().args.end:
                endtime = ts_to_dt(config.CFG().args.end)

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
                if self.writeback_es.indices.exists(config.CFG().writeback_alias):
                    return
            except ConnectionError:
                pass
            time.sleep(1.0)

        if self.writeback_es.ping():
            log.error(
                'Writeback alias "%s" does not exist, did you run `elastalert-create-index`?',
                config.CFG().writeback_alias,
            )
        else:
            log.error(
                'Could not reach ElasticSearch at "%s:%d".',
                config.CFG().es_client.es_host,
                config.CFG().es_client.es_port,
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
        new_rule_hashes = self.rules_loader.get_hashes(config.CFG().args.rule)

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
                    new_rule = self.rules_loader.load_rule(rule_name)
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
                self.rules[rule_name] = self.init_rule(new_rule, False, rule_name)

        # Load new rules
        if not config.CFG().args.rule:
            for rule_name in set(new_rule_hashes.keys()) - set(self.rule_hashes.keys()):
                try:
                    new_rule = self.rules_loader.load_rule(rule_name)
                    if "is_enabled" in new_rule and not new_rule["is_enabled"]:
                        continue
                    if new_rule["identifier"] in self.rules:
                        raise EAException(
                            "A rule with the name %s already exists"
                            % (new_rule["name"])
                        )
                except EAException as e:
                    self.handle_error("Could not load rule %s: %s" % (rule_name, e))
                    self.send_notification_email(exception=e, rule_file=rule_name)
                    continue
                if self.init_rule(new_rule):
                    log.info("Loaded new rule %s" % rule_name)
                    self.rules[rule_name] = new_rule

        self.rule_hashes = new_rule_hashes
        log.info("Background configuration change check run at %s", pretty_ts(ts_now()))

    def handle_rule_execution(self, rule_config):
        next_run = datetime.datetime.utcnow() + rule_config["run_every"]
        # Set endtime based on the rule's delay
        delay = rule_config.get("query_delay")
        if hasattr(config.CFG().args, "end") and config.CFG().args.end:
            endtime = ts_to_dt(config.CFG().args.end)
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
            starttime, endtime, num_matches, alerts_sent = rule_config["type"].run_rule(
                endtime
            )
        except EARuntimeException as e:
            self.handle_error(
                "Error running rule %s: %s" % (rule_config["name"], e.msg),
                {"rule": rule_config["name"]},
            )
        except Exception as e:
            self.handle_uncaught_exception(e, rule_config)
        else:
            old_starttime = pretty_ts(starttime)
            log.info(
                "Ran %s from %s to %s: %s matches," " %s alerts sent",
                rule_config["name"],
                old_starttime,
                pretty_ts(endtime, rule_config.get("use_local_time")),
                num_matches,
                alerts_sent,
            )

            if next_run < datetime.datetime.utcnow():
                # We were processing for longer than our refresh interval
                # This can happen if --start was specified with a large time period
                # or if we are running too slow to process events in real time.
                log.warning(
                    "Querying from %s to %s took longer than %s!"
                    % (
                        old_starttime,
                        pretty_ts(endtime, rule_config.get("use_local_time")),
                        config.CFG().run_every,
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
        log.info("Sleeping for %s seconds" % duration)
        time.sleep(duration)

    def writeback(self, doc_type, body, rule=None, match_body=None):
        writeback_body = body

        for key in list(writeback_body.keys()):
            # Convert any datetime objects to timestamps
            if isinstance(writeback_body[key], datetime.datetime):
                writeback_body[key] = dt_to_ts(writeback_body[key])

        if config.CFG().debug:
            log.info("Skipping writing to ES: %s" % writeback_body)
            return None

        if "@timestamp" not in writeback_body:
            writeback_body["@timestamp"] = dt_to_ts(ts_now())

        try:
            index = self.writeback_es.resolve_writeback_index(
                config.CFG().writeback_index, doc_type
            )
            if self.writeback_es.is_atleastsixtwo():
                res = self.writeback_es.index(index=index, body=body)
            else:
                res = self.writeback_es.index(index=index, doc_type=doc_type, body=body)
            return res
        except ElasticsearchException as e:
            log.exception("Error writing alert info to Elasticsearch: %s" % e)

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
            res = self.writeback_es.search(
                index=config.CFG().writeback_index, body=query, size=1000
            )
            if res["hits"]["hits"]:
                return res["hits"]["hits"]
        except ElasticsearchException as e:
            log.exception("Error finding recent pending alerts: %s %s", e, query)
        return []

    def alert(
        self, matches: List, rule_config: dict, alert_time=None, retried: bool = False
    ):
        rule_config["type"].send_alert(matches, alert_time, retried)

    def send_pending_alerts(self):
        pending_alerts = self.find_recent_pending_alerts(config.CFG().alert_time_limit)
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
                    self.writeback_es.delete(index=config.CFG().writeback_index, id=_id)
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
            "query": {"query_string": {"query": "aggregate_id:'%s'" % _id}},
            "sort": {"@timestamp": "asc"},
        }
        matches = []
        try:
            if self.writeback_es.is_atleastsixtwo():
                res = self.writeback_es.search(
                    index=config.CFG().writeback_index,
                    body=query,
                    size=config.CFG().max_aggregation,
                )
            else:
                res = self.writeback_es.deprecated_search(
                    index=config.CFG().writeback_index,
                    doc_type="elastalert",
                    body=query,
                    size=config.CFG().max_aggregation,
                )
            for match in res["hits"]["hits"]:
                matches.append(match["_source"])
                if self.writeback_es.is_atleastsixtwo():
                    self.writeback_es.delete(
                        index=config.CFG().writeback_index, id=match["_id"]
                    )
                else:
                    self.writeback_es.delete(
                        index=config.CFG().writeback_index,
                        doc_type="elastalert",
                        id=match["_id"],
                    )
        except (KeyError, ElasticsearchException) as e:
            self.handle_error("Error fetching aggregated matches: %s" % e, {"id": _id})
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
                    index=config.CFG().writeback_index, body=query, size=1
                )
            else:
                res = self.writeback_es.deprecated_search(
                    index=config.CFG().writeback_index,
                    doc_type="elastalert",
                    body=query,
                    size=1,
                )
            if len(res["hits"]["hits"]) == 0:
                return None
        except (KeyError, ElasticsearchException) as e:
            self.handle_error(
                "Error searching for pending aggregated matches: %s" % e,
                {"rule_name": rule["name"]},
            )
            return None

        return res["hits"]["hits"][0]

    def silence(self, silence_cache_key=None):
        """ Silence an alert for a period of time. --silence and --rule must be passed as args. """
        if config.CFG().debug:
            log.error("--silence not compatible with --debug")
            exit(1)

        if not config.CFG().args.rule:
            log.error("--silence must be used with --rule")
            exit(1)

        # With --rule, self.rules will only contain that specific rule

        first_rule = next(iter(self.rules.values()))
        if not silence_cache_key:
            silence_cache_key = first_rule["name"] + "._silence"

        try:
            silence_ts = parse_deadline(config.CFG().args.silence)
        except (ValueError, TypeError):
            log.error("%s is not a valid time period" % config.CFG().args.silence)
            exit(1)

        if not first_rule["type"].set_realert(silence_cache_key, silence_ts, 0):
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
        if config.CFG().disable_rules_on_error:
            del self.rules[rule["name"]]
            self.disabled_rules[rule["name"]] = rule
            self.scheduler.pause_job(job_id=rule["name"])
            log.info("Rule %s disabled", rule["name"])
        if config.CFG().mail_settings:
            self.send_notification_email(exception=exception, rule=rule)

    def send_notification_email(
        self, text="", exception=None, rule=None, subject=None, rule_file=None
    ):
        mail_settings = config.CFG().mail_settings
        email_body = text
        rule_name = None
        if rule:
            rule_name = rule["name"]
        elif rule_file:
            rule_name = rule_file
        if exception and rule_name:
            if not subject:
                subject = "Uncaught exception in ElastAlert - %s" % rule_name
            email_body += "\n\n"
            email_body += "The rule %s has raised an uncaught exception.\n\n" % (
                rule_name
            )
            if config.CFG().disable_rules_on_error:
                modified = (
                    " or if the rule config file has been modified"
                    if not config.CFG().args.pin_rules
                    else ""
                )
                email_body += (
                    "It has been disabled and will be re-enabled when ElastAlert restarts%s.\n\n"
                    % modified
                )
            tb = traceback.format_exc()
            email_body += tb
        email = MIMEText(email_body)
        email["Subject"] = subject if subject else "ElastAlert notification"
        recipients = config.CFG().mail_settings.notify_email
        if rule and rule.get("notify_email"):
            if isinstance(rule["notify_email"], str):
                rule["notify_email"] = [rule["notify_email"]]
            recipients = recipients + rule["notify_email"]
        recipients = list(set(recipients))
        email["To"] = ", ".join(recipients)
        email["From"] = mail_settings.from_addr
        email["Reply-To"] = mail_settings.email_reply_to or email["To"]

        try:
            smtp = SMTP(mail_settings.smtp_host)
            smtp.sendmail(mail_settings.from_addr, recipients, email.as_string())
        except (SMTPException, error) as e:
            self.handle_error(
                "Error connecting to SMTP host: %s" % e, {"email_body": email_body}
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
    if not config.CFG().args.silence:
        client.start()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
