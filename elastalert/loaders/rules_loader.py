import copy
import datetime
import logging
import os
import sys
from abc import ABCMeta, abstractmethod
from typing import Dict, List, Optional, Union

import jsonschema
import yaml
from elastalert import alerter, config, enhancements, ruletypes
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


def remove_top_level_filter_query(rule_config):
    """
    Mutates Rule-Configs so they can be defined as sigma generated configs
    Removes the Top-Level "query" element from the dict from the filter element
    @param rule_config: Rule Configuration to mutate
    """
    new_filters = []
    for es_filter in rule_config.get("filter", []):
        if es_filter.get("query"):
            new_filters.append(es_filter["query"])
        else:
            new_filters.append(es_filter)
    rule_config["filter"] = new_filters


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
        "spike_aggregation": ruletypes.SpikeMetricAggregationRule,
        "correlation": ruletypes.CorrelationRule,
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

    def __init__(self, conf: config.Config):
        with open(
            os.path.join(os.path.dirname(__file__), "schema.yaml")
        ) as schema_file:
            # schema for rule yaml
            self.rule_schema = jsonschema.Draft7Validator(yaml.safe_load(schema_file))

        self.base_config: config.Config = copy.deepcopy(conf)

    def load(self, args=None) -> Dict[str, dict]:
        rule_names = self.get_names(config.CFG().args.rule)
        rule_configs = (self.load_rule(rule_name) for rule_name in rule_names)
        loaded_rule_configs = {}
        for rule_name, rule_config in zip(rule_names, rule_configs):
            if not rule_config:
                continue
            rule_name = rule_config["name"]
            if "is_enabled" in rule_config and not rule_config["is_enabled"]:
                log.debug("Diabled rule %s", rule_name)
                continue
            try:
                self.load_modules(rule_config, args)
            except EAException as e:
                log.error("Unable to instantiate rule %s: %s", rule_name, e)
                continue
            loaded_rule_configs[rule_name] = rule_config
        return loaded_rule_configs

    @abstractmethod
    def get_hashes(self, use_rule: str = None) -> Dict[str, int]:
        """
        Discover and get the hashes of all the rules as defined in the conf.
        :param use_rule: Get only the hash of this rule if the parameter is not None
        :return: Dict of rule name to hash. The hash is an integer
        :rtype: dict
        """

    @abstractmethod
    def get_rule_config(self, name: str) -> dict:
        """
        Gets the rule config for a rule name
        :param name: The rule name
        :return dict: The rule config
        """

    @abstractmethod
    def get_names(self, use_rule: str = None) -> List[str]:
        """
        Get the names of all rules in a form that get_rule_config(name) can load the rule
        :param use_rule: Get only the name of this rule if the parameter is not None
        :return: List of rule names
        """

    def get_import_rule(self, rule_config: dict) -> str:
        """
        Retrieve the name of the rule to import.
        :param dict rule_config: Rule config dict
        :return: rule name
        :rtype: str
        """
        return rule_config["import"]

    def load_rule(self, rule_path: str, imports: list = None) -> Optional[dict]:

        # recursive load rule (with imports)
        def _load(_rule_path: str, _imports: list = None) -> dict:
            _rule_config = self.get_rule_config(_rule_path)
            remove_top_level_filter_query(_rule_config)
            if "import" in _rule_config:
                if _imports is None:
                    _imports = []
                _rule_config["rule_file"] = _rule_path
                import_rule_name = self.get_import_rule(_rule_config)
                if import_rule_name in _imports:
                    raise EAException("Import loop detected")
                self.import_rules.setdefault(_rule_path, [])
                self.import_rules[_rule_path].append(import_rule_name)
                _imports.append(import_rule_name)
                inner_rule = _load(import_rule_name, _imports)

                # Special case for merging filters - if both files specify a filter merge (AND) them
                if "filter" in inner_rule and "filter" in _rule_config:
                    _rule_config["filter"] = (
                        inner_rule["filter"] + _rule_config["filter"]
                    )

                inner_rule.update(_rule_config)
                _rule_config = inner_rule
            return _rule_config

        rule_config = _load(rule_path, imports)
        try:
            # parse config
            self.parse_rule_config(rule_path, rule_config)
        except EAConfigException as e:
            log.error("Invalid rule % skipped: %s", rule_path, e)
            return None
        return rule_config

    def parse_rule_config(self, rule_name: str, rule_config: dict):
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
        rule_config.setdefault("alert_text", self.base_config.alert_text)
        rule_config.setdefault("alert_text_args", self.base_config.alert_text_args)
        rule_config.setdefault("alert_text_type", self.base_config.alert_text_type)
        rule_config.setdefault("buffer_time", self.base_config.buffer_time)
        rule_config.setdefault("run_every", self.base_config.run_every)

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

        # set the identifier for access in self.rule (elastalert)
        rule_config["identifier"] = rule_name

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
        if self.base_config.es_client.verify_certs:
            rule_config.setdefault(
                "verify_certs", self.base_config.es_client.verify_certs
            )
            rule_config.setdefault("ca_certs", self.base_config.es_client.ca_certs)
            rule_config.setdefault(
                "client_cert", self.base_config.es_client.client_cert
            )
            rule_config.setdefault("client_key", self.base_config.es_client.client_key)

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
        if (
            rule_config.get("use_count_query") or rule_config.get("use_terms_query")
        ) and "doc_type" not in rule_config:
            raise EAConfigException("doc_type must be specified.")

        # Check that query_key is set if use_terms_query
        if rule_config.get("use_terms_query") and "query_key" not in rule_config:
            raise EAConfigException("query_key must be specified with use_terms_query")

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
            rule_config["type"] = rule_config["type"](rule_config, args)
        except (KeyError, EAException) as e:
            raise EAConfigException(
                "Error initializing rule %s: %s" % (rule_config["name"], e)
            ).with_traceback(sys.exc_info()[2])
        # Instantiate alerts only if we're not in debug mode
        # In debug mode alerts are not actually sent so don't bother instantiating them
        if not (args and args.debug):
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
