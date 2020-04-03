import copy
import datetime
import logging
import os
import sys
from abc import ABCMeta, abstractmethod
from typing import Dict, List, Union

import jsonschema
import yaml
from elastalert import alerter, enhancements, ruletypes
from elastalert.alerter import Alerter
from elastalert.alerter.opsgenie_alerter import OpsGenieAlerter
from elastalert.exceptions import EAConfigException, EAException
from elastalert.utils.time import (
    dt_to_ts,
    dt_to_ts_with_format,
    dt_to_unix,
    dt_to_unixms,
    ts_to_dt,
    ts_to_dt_with_format,
    unix_to_dt,
    unixms_to_dt,
)
from elastalert.utils.util import get_module

log = logging.getLogger(__name__)


class RulesLoader(metaclass=ABCMeta):
    # import rule dependency
    import_rules = {}

    # Required global (config.yaml) configuration options for the loader
    required_globals = frozenset([])

    # Required local (rule.yaml) configuration options
    required_locals = frozenset(["alert", "type", "name", "index"])

    # Used to map the names of rules to their classes
    rules_mapping = {
        "frequency": ruletypes.FrequencyRule,
        "any": ruletypes.AnyRule,
        "spike": ruletypes.SpikeRule,
        "blacklist": ruletypes.BlacklistRule,
        "whitelist": ruletypes.WhitelistRule,
        "change": ruletypes.ChangeRule,
        "flatline": ruletypes.FlatlineRule,
        "new_term": ruletypes.NewTermsRule,
        "cardinality": ruletypes.CardinalityRule,
        "metric_aggregation": ruletypes.MetricAggregationRule,
        "percentage_match": ruletypes.PercentageMatchRule,
    }

    # Used to map names of alerts to their classes
    alerts_mapping = {
        "email": alerter.EmailAlerter,
        "jira": alerter.JiraAlerter,
        "opsgenie": OpsGenieAlerter,
        "stomp": alerter.StompAlerter,
        "debug": alerter.DebugAlerter,
        "command": alerter.CommandAlerter,
        "sns": alerter.SnsAlerter,
        "hipchat": alerter.HipChatAlerter,
        "stride": alerter.StrideAlerter,
        "ms_teams": alerter.MsTeamsAlerter,
        "slack": alerter.SlackAlerter,
        "mattermost": alerter.MattermostAlerter,
        "pagerduty": alerter.PagerDutyAlerter,
        "exotel": alerter.ExotelAlerter,
        "twilio": alerter.TwilioAlerter,
        "victorops": alerter.VictorOpsAlerter,
        "telegram": alerter.TelegramAlerter,
        "googlechat": alerter.GoogleChatAlerter,
        "gitter": alerter.GitterAlerter,
        "servicenow": alerter.ServiceNowAlerter,
        "alerta": alerter.AlertaAlerter,
        "post": alerter.HTTPPostAlerter,
        "hivealerter": alerter.HiveAlerter,
    }

    # A partial ordering of alert types. Relative order will be preserved in the resulting alerts list
    # For example, jira goes before email so the ticket # will be added to the resulting email.
    alerts_order = {"jira": 0, "email": 1}

    base_config = {}

    def __init__(self, conf: dict):
        with open(
            os.path.join(os.path.dirname(__file__), "schema.yaml")
        ) as schema_file:
            # schema for rule yaml
            self.rule_schema = jsonschema.Draft7Validator(yaml.safe_load(schema_file))

        self.base_config = copy.deepcopy(conf)

    def load(self, conf: dict, args=None) -> Dict[str, dict]:
        # TODO rule_name as argument
        rule_configs = self.get_rule_configs(conf)
        loaded_rule_configs = dict()
        for rule_name, rule_config in rule_configs.items():
            try:
                self.parse_rule_config(rule_name, rule_config, conf)
            except EAConfigException as e:
                log.error("Invalid rule % skipped: %s", rule_name, e)
                continue
            if "is_enabled" in rule_config and not rule_config["is_enabled"]:
                log.debug("Diabled rule %s", rule_name)
                continue
            try:
                self.load_modules(rule_config)
            except EAException as e:
                log.error("Unable to instantiate rule %s: %s", rule_name, e)
                continue
            loaded_rule_configs[rule_name] = rule_config
        return loaded_rule_configs

    @abstractmethod
    def get_rule_configs(self, conf: dict) -> Dict[str, dict]:
        """
        Loads the rule configurations

        :param dict conf: The global configuration
        :return Dict[str, dict]: A dict with the rule configs. The key is the rule name and value is the config
        """

    @abstractmethod
    def get_hashes(self, conf: dict, use_rule: str = None) -> Dict[str, str]:
        """
        Discover and get the hashes of all the rules as defined in the conf.
        :param dict conf: Configuration
        :param str use_rule: Limit to only specified rule
        :return: Dict of rule name to hash
        :rtype: dict
        """

    @abstractmethod
    def get_rule_config(self, name: str) -> dict:
        """
        Gets the rule config for a rule name

        :param name: The rule name
        :return dict: The rule config
        """

    def get_import_rule(self, rule_config: dict) -> str:
        """
        Retrieve the name of the rule to import.
        :param dict rule: Rule dict
        :return: rule name
        :rtype: str
        """
        return rule_config["import"]

    def load_rule(self, rule_name: str, imports: list = None) -> dict:
        rule_config = self.get_rule_config(rule_name)
        if "import" in rule_config:
            import_rule_name = self.get_import_rule(rule_config)
            if import_rule_name in imports:
                raise EAException("Import loop detected")
            self.import_rules[rule_name] = import_rule_name
            if imports is None:
                imports = list()
            imports.append(import_rule_name)
            rule_config.update(self.load_rule(import_rule_name, imports))
        return rule_config

    def parse_rule_config(self, rule_name: str, rule_config: dict, conf: dict):
        try:
            self.rule_schema.validate(rule_config)
        except jsonschema.ValidationError as e:
            raise EAConfigException("Invalid rule: %s\n%s" % (rule_name, e))

        try:
            # Set all time based parameters
            if "timeframe" in rule_config:
                rule_config["timeframe"] = datetime.timedelta(
                    **rule_config["timeframe"]
                )
            if "realert" in rule_config:
                rule_config["realert"] = datetime.timedelta(**rule_config["realert"])
            else:
                if "aggregation" in rule_config:
                    rule_config["realert"] = datetime.timedelta(minutes=0)
                else:
                    rule_config["realert"] = datetime.timedelta(minutes=1)
            if "aggregation" in rule_config and not rule_config["aggregation"].get(
                "schedule"
            ):
                rule_config["aggregation"] = datetime.timedelta(
                    **rule_config["aggregation"]
                )
            if "query_delay" in rule_config:
                rule_config["query_delay"] = datetime.timedelta(
                    **rule_config["query_delay"]
                )
            if "buffer_time" in rule_config:
                rule_config["buffer_time"] = datetime.timedelta(
                    **rule_config["buffer_time"]
                )
            if "run_every" in rule_config:
                rule_config["run_every"] = datetime.timedelta(
                    **rule_config["run_every"]
                )
            if "bucket_interval" in rule_config:
                rule_config["bucket_interval_timedelta"] = datetime.timedelta(
                    **rule_config["bucket_interval"]
                )
            if "exponential_realert" in rule_config:
                rule_config["exponential_realert"] = datetime.timedelta(
                    **rule_config["exponential_realert"]
                )
            if "kibana4_start_timedelta" in rule_config:
                rule_config["kibana4_start_timedelta"] = datetime.timedelta(
                    **rule_config["kibana4_start_timedelta"]
                )
            if "kibana4_end_timedelta" in rule_config:
                rule_config["kibana4_end_timedelta"] = datetime.timedelta(
                    **rule_config["kibana4_end_timedelta"]
                )
            if "kibana_discover_from_timedelta" in rule_config:
                rule_config["kibana_discover_from_timedelta"] = datetime.timedelta(
                    **rule_config["kibana_discover_from_timedelta"]
                )
            if "kibana_discover_to_timedelta" in rule_config:
                rule_config["kibana_discover_to_timedelta"] = datetime.timedelta(
                    **rule_config["kibana_discover_to_timedelta"]
                )
        except (KeyError, TypeError) as e:
            raise EAException("Invalid time format used: %s" % e)

        # Set defaults, copy defaults from config.yaml
        for key, val in list(self.base_config.items()):
            rule_config.setdefault(key, val)
        rule_config.setdefault("name", rule_name)
        rule_config.setdefault("realert", datetime.timedelta(seconds=0))
        rule_config.setdefault("aggregation", datetime.timedelta(seconds=0))
        rule_config.setdefault("query_delay", datetime.timedelta(seconds=0))
        rule_config.setdefault("timestamp_field", "@timestamp")
        rule_config.setdefault("filter", [])
        rule_config.setdefault("timestamp_type", "iso")
        rule_config.setdefault("timestamp_format", "%Y-%m-%dT%H:%M:%SZ")
        rule_config.setdefault("_source_enabled", True)
        rule_config.setdefault("use_local_time", True)
        rule_config.setdefault("description", "")

        # Set timestamp_type conversion function, used when generating queries and processing hits
        rule_config["timestamp_type"] = rule_config["timestamp_type"].strip().lower()
        if rule_config["timestamp_type"] == "iso":
            rule_config["ts_to_dt"] = ts_to_dt
            rule_config["dt_to_ts"] = dt_to_ts
        elif rule_config["timestamp_type"] == "unix":
            rule_config["ts_to_dt"] = unix_to_dt
            rule_config["dt_to_ts"] = dt_to_unix
        elif rule_config["timestamp_type"] == "unix_ms":
            rule_config["ts_to_dt"] = unixms_to_dt
            rule_config["dt_to_ts"] = dt_to_unixms
        elif rule_config["timestamp_type"] == "custom":

            def _ts_to_dt_with_format(ts):
                return ts_to_dt_with_format(
                    ts, ts_format=rule_config["timestamp_format"]
                )

            def _dt_to_ts_with_format(dt):
                ts = dt_to_ts_with_format(dt, ts_format=rule_config["timestamp_format"])
                if "timestamp_format_expr" in rule_config:
                    # eval expression passing 'ts' and 'dt'
                    return eval(
                        rule_config["timestamp_format_expr"], {"ts": ts, "dt": dt}
                    )
                else:
                    return ts

            rule_config["ts_to_dt"] = _ts_to_dt_with_format
            rule_config["dt_to_ts"] = _dt_to_ts_with_format
        else:
            raise EAException("timestamp_type must be one of iso, unix, or unix_ms")

        # Add support for client ssl certificate auth
        if "verify_certs" in conf:
            rule_config.setdefault("verify_certs", conf.get("verify_certs"))
            rule_config.setdefault("ca_certs", conf.get("ca_certs"))
            rule_config.setdefault("client_cert", conf.get("client_cert"))
            rule_config.setdefault("client_key", conf.get("client_key"))

        # Set HipChat options from global config
        rule_config.setdefault("hipchat_msg_color", "red")
        rule_config.setdefault("hipchat_domain", "api.hipchat.com")
        rule_config.setdefault("hipchat_notify", True)
        rule_config.setdefault("hipchat_from", "")
        rule_config.setdefault("hipchat_ignore_ssl_errors", False)

        # Make sure we have required options
        if self.required_locals - frozenset(list(rule_config.keys())):
            raise EAConfigException(
                "Missing required option(s): %s"
                % (
                    ", ".join(
                        self.required_locals - frozenset(list(rule_config.keys()))
                    )
                )
            )

        if "include" in rule_config and type(rule_config["include"]) != list:
            raise EAConfigException("include option must be a list")

        raw_query_key = rule_config.get("query_key")
        if isinstance(raw_query_key, list):
            if len(raw_query_key) > 1:
                rule_config["compound_query_key"] = raw_query_key
                rule_config["query_key"] = ",".join(raw_query_key)
            elif len(raw_query_key) == 1:
                rule_config["query_key"] = raw_query_key[0]
            else:
                del rule_config["query_key"]

        if isinstance(rule_config.get("aggregation_key"), list):
            rule_config["compound_aggregation_key"] = rule_config["aggregation_key"]
            rule_config["aggregation_key"] = ",".join(rule_config["aggregation_key"])

        if isinstance(rule_config.get("compare_key"), list):
            rule_config["compound_compare_key"] = rule_config["compare_key"]
            rule_config["compare_key"] = ",".join(rule_config["compare_key"])
        elif "compare_key" in rule_config:
            rule_config["compound_compare_key"] = [rule_config["compare_key"]]
        # Add QK, CK and timestamp to include
        include = rule_config.get("include", ["*"])
        if "query_key" in rule_config:
            include.append(rule_config["query_key"])
        if "compound_query_key" in rule_config:
            include += rule_config["compound_query_key"]
        if "compound_aggregation_key" in rule_config:
            include += rule_config["compound_aggregation_key"]
        if "compare_key" in rule_config:
            include.append(rule_config["compare_key"])
        if "compound_compare_key" in rule_config:
            include += rule_config["compound_compare_key"]
        if "top_count_keys" in rule_config:
            include += rule_config["top_count_keys"]
        include.append(rule_config["timestamp_field"])
        rule_config["include"] = list(set(include))

        # Check that generate_kibana_url is compatible with the filters
        if rule_config.get("generate_kibana_link"):
            for es_filter in rule_config.get("filter"):
                if es_filter:
                    if "not" in es_filter:
                        es_filter = es_filter["not"]
                    if "query" in es_filter:
                        es_filter = es_filter["query"]
                    if list(es_filter.keys())[0] not in (
                        "term",
                        "query_string",
                        "range",
                    ):
                        raise EAConfigException(
                            "generate_kibana_link is incompatible with filters other than term, query_string and range."
                            "Consider creating a dashboard and using use_kibana_dashboard instead."
                        )

        # Check that doc_type is provided if use_count/terms_query
        if rule_config.get("use_count_query") or rule_config.get("use_terms_query"):
            if "doc_type" not in rule_config:
                raise EAConfigException("doc_type must be specified.")

        # Check that query_key is set if use_terms_query
        if rule_config.get("use_terms_query"):
            if "query_key" not in rule_config:
                raise EAConfigException(
                    "query_key must be specified with use_terms_query"
                )

        # Warn if use_strf_index is used with %y, %M or %D
        # (%y = short year, %M = minutes, %D = full date)
        if rule_config.get("use_strftime_index"):
            for token in ["%y", "%M", "%D"]:
                if token in rule_config.get("index"):
                    log.warning(
                        "Did you mean to use %s in the index? "
                        "The index will be formatted like %s"
                        % (
                            token,
                            datetime.datetime.now().strftime(rule_config.get("index")),
                        )
                    )

        if rule_config.get("scan_entire_timeframe") and not rule_config.get(
            "timeframe"
        ):
            raise EAConfigException(
                "scan_entire_timeframe can only be used if there is a timeframe specified"
            )

    def load_modules(self, rule_config: dict, args=None):
        """ Loads things that could be modules. Enhancements, alerts and rule type. """
        # Set match enhancements
        match_enhancements = []
        for enhancement_name in rule_config.get("match_enhancements", []):
            if enhancement_name in dir(enhancements):
                enhancement = getattr(enhancements, enhancement_name)
            else:
                enhancement = get_module(enhancement_name)
            if not issubclass(enhancement, enhancements.BaseEnhancement):
                raise EAConfigException(
                    "Enhancement module %s not a subclass of BaseEnhancement"
                    % enhancement_name
                )
            match_enhancements.append(enhancement(rule_config))
        rule_config["match_enhancements"] = match_enhancements

        # Convert rule type into RuleType object
        if rule_config["type"] in self.rules_mapping:
            rule_config["type"] = self.rules_mapping[rule_config["type"]]
        else:
            rule_config["type"] = get_module(rule_config["type"])
            if not issubclass(rule_config["type"], ruletypes.RuleType):
                raise EAConfigException(
                    "Rule module %s is not a subclass of RuleType"
                    % (rule_config["type"])
                )

        # Make sure we have required alert and type options
        reqs = rule_config["type"].required_options

        if reqs - frozenset(list(rule_config.keys())):
            raise EAConfigException(
                "Missing required option(s): %s"
                % (", ".join(reqs - frozenset(list(rule_config.keys()))))
            )
        # Instantiate rule
        try:
            rule_config["type"] = rule_config["type"](rule_config)
        except (KeyError, EAException) as e:
            raise EAConfigException(
                "Error initializing rule %s: %s" % (rule_config["name"], e)
            ).with_traceback(sys.exc_info()[2])
        # Instantiate alerts only if we're not in debug mode
        # In debug mode alerts are not actually sent so don't bother instantiating them
        if not args or not args.debug:
            rule_config["alert"] = self.load_alerts(
                rule_config, alert_field=rule_config["alert"]
            )

    def load_alerts(
        self, rule_config: dict, alert_field: Union[str, list]
    ) -> List[Alerter]:
        def normalize_config(alert: Union[str, dict]):
            """Alert config entries are either "alertType" or {"alertType": {"key": "data"}}.
            This function normalizes them both to the latter format. """
            if isinstance(alert, str):
                return alert, rule_config
            elif isinstance(alert, dict):
                name, config = next(iter(list(alert.items())))
                config_copy = copy.copy(rule_config)
                config_copy.update(
                    config
                )  # warning, this (intentionally) mutates the rule dict
                return name, config_copy
            else:
                raise EAConfigException()

        def create_alert(alert: str, alert_config: dict):
            alert_class = self.alerts_mapping.get(alert) or get_module(alert)
            if not issubclass(alert_class, alerter.Alerter):
                raise EAConfigException(
                    "Alert module %s is not a subclass of Alerter" % alert
                )
            missing_options = (
                rule_config["type"].required_options | alert_class.required_options
            ) - frozenset(alert_config or [])
            if missing_options:
                raise EAConfigException(
                    "Missing required option(s): %s" % (", ".join(missing_options))
                )
            return alert_class(alert_config)

        try:
            if type(alert_field) != list:
                alert_field = [alert_field]

            alert_field = [normalize_config(x) for x in alert_field]
            alert_field = sorted(
                alert_field, key=lambda a_b: self.alerts_order.get(a_b[0], 1)
            )
            # Convert all alerts into Alerter objects
            alert_field = [create_alert(a, b) for a, b in alert_field]

        except (KeyError, EAException) as e:
            raise EAConfigException(
                "Error initiating alert %s: %s" % (rule_config["alert"], e)
            ).with_traceback(sys.exc_info()[2])

        return alert_field
