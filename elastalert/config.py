import argparse
import datetime
import logging
import logging.config
from dataclasses import dataclass, field
from typing import Optional

import staticconf.loader
from elastalert.exceptions import EAConfigException
from envparse import Env

log = logging.getLogger(__name__)


class Parser(object):
    @classmethod
    def parse_duration(cls, value):
        """Convert ``unit=num`` spec into a ``timedelta`` object."""
        unit, num = value.split("=")
        return datetime.timedelta(**{unit: int(num)})

    @classmethod
    def parse_args(cls, args) -> argparse.Namespace:
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
            help="Run only a specific rule "
            "(by filename, must still be in rules folder)",
        )
        parser.add_argument(
            "--silence",
            dest="silence",
            help="Silence rule for a time period. Must be used with --rule. Usage: "
            "--silence <units>=<number>, eg. --silence hours=2",
        )
        parser.add_argument(
            "--silence_qk_value",
            dest="silence_qk_value",
            help="Silence the rule only for this specific query key value.",
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
            type=cls.parse_duration,
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
            help="Enable logging from Elasticsearch queries as curl command."
            "Queries will be logged to file. Note that "
            "this will incorrectly display localhost:9200 as the host/port",
        )
        return parser.parse_args(args)


@dataclass(frozen=True)
class ESClient(object):
    es_host: str
    es_port: int
    es_username: str = None
    es_password: str = None
    aws_region: str = None
    aws_profile: str = None
    use_ssl: bool = False
    verify_certs: bool = False
    es_url_prefix: str = ""
    ca_certs: str = None
    client_cert: str = None
    client_key: str = None
    es_conn_timeout: int = 20
    es_send_get_body_as: str = "GET"


@dataclass(frozen=True)
class MailSettings(object):
    notify_email: list
    from_addr: str = "ElastAlert"
    smtp_host: str = "localhost"
    email_reply_to: str = None


def default_alert_text_args():
    return [
        "_index",
        "@timestamp",
        "beat.name",
        "user_name",
        "host_name",
        "log_name",
        "z_original_message",
    ]


default_alert_text = (
    "Index: {0} \nEvent_Timestamp: {1} \nBeat_Name: {2} "
    "\nUser_Name: {3} "
    "\nHost_Name: {4} "
    "\nLog_Name: {5} \nOriginal_Message: \n\n{6} "
)


@dataclass(frozen=True)
class Config(object):
    es_client: ESClient
    rules_folder: str
    run_every: datetime.timedelta
    buffer_time: datetime.timedelta
    writeback_index: str
    alert_time_limit: datetime.timedelta = None
    debug: bool = False
    old_query_limit: datetime.timedelta = None
    args: argparse.Namespace = None
    mail_settings: MailSettings = None
    alert_text: str = default_alert_text
    alert_text_type: str = "alert_text_only"
    alert_text_args: list = field(default_factory=default_alert_text_args)
    replace_dots_in_field_names: bool = False
    string_multi_field_name: bool = False
    add_metadata_alert: bool = False
    logging: dict = None
    writeback_alias: str = "elastalert_alerts"
    max_query_size: int = 10000
    show_disabled_rules: bool = True
    max_aggregation: int = 10000
    scroll_keepalive: str = "30s"
    max_scrolling_count: int = 0
    disable_rules_on_error: bool = True
    scan_subdirectories: bool = True
    rules_loader: str = "file"

    @classmethod
    def load_config(cls, args):

        # Required global (config.yaml) configuration options
        required_globals = frozenset(
            ["run_every", "es_client", "writeback_index", "buffer_time"]
        )

        args = Parser.parse_args(args)
        filename = args.config or "config.yaml"
        try:
            conf = staticconf.loader.yaml_loader(filename)
        except FileNotFoundError:
            raise EAConfigException("Config file '{}' not found".format(filename))

        conf["args"] = args

        # Settings that can be derived from ENV variables
        env_settings = {
            "ES_USE_SSL": "use_ssl",
            "ES_PASSWORD": "es_password",
            "ES_USERNAME": "es_username",
            "ES_HOST": "es_host",
            "ES_PORT": "es_port",
            "ES_URL_PREFIX": "es_url_prefix",
        }

        env = Env(ES_USE_SSL=bool)

        for env_var, conf_var in env_settings.items():
            val = env(env_var, None)
            if val is not None:
                conf["es_client"][conf_var] = val

        conf["es_client"] = ESClient(**conf["es_client"])
        conf["mail_settings"] = (
            MailSettings(**conf["mail_settings"])
            if "mail_settings" in conf
            else MailSettings(notify_email=[])
        )

        # init logging from config and set log levels according to command line options

        conf["debug"] = True if args.debug else False

        # Make sure we have all required globals
        if required_globals - frozenset(list(conf.keys())):
            raise EAConfigException(
                "%s must contain %s"
                % (filename, ", ".join(required_globals - frozenset(list(conf.keys()))))
            )

        # Convert run_every, buffer_time into a timedelta object

        # TODO change to default values in dataclass
        conf.setdefault("alert_time_limit", {"days": 2})
        conf.setdefault("old_query_limit", {"weeks": 1})

        try:
            conf["run_every"] = datetime.timedelta(**conf["run_every"])
            conf["buffer_time"] = datetime.timedelta(**conf["buffer_time"])
            conf["alert_time_limit"] = datetime.timedelta(**conf["alert_time_limit"])
            conf["old_query_limit"] = datetime.timedelta(**conf["old_query_limit"])
        except (KeyError, TypeError) as e:
            raise EAConfigException("Invalid time format used: %s" % e)
        config = cls(**conf)
        configure_logging(args, config)
        return config


def configure_logging(args, config: Config) -> None:
    # configure logging from config file if provided
    if config.logging:
        # load new logging config
        logging.config.dictConfig(config.logging)
    else:
        logging.basicConfig()

    if args.verbose and args.debug:
        log.info("Note: --debug and --verbose flags are set. --debug takes precedent.")

    # re-enable INFO log level on elastalert_logger in verbose/debug mode
    # (but don't touch it if it is already set to INFO or below by config)
    if (args.verbose or args.debug) and (
        log.level > logging.INFO or log.level == logging.NOTSET
    ):
        logging.getLogger("elastalert").setLevel(logging.INFO)

    if args.debug:
        log.info(
            "Note: In debug mode, alerts will be logged to console but "
            "NOT actually sent. To send them but remain "
            "verbose, use --verbose instead. "
        )
        logging.getLogger("elastalert").setLevel(logging.DEBUG)

    if not (args.es_debug or config.logging):
        logging.getLogger("elasticsearch").setLevel(logging.WARNING)

    if args.es_debug_trace:
        tracer = logging.getLogger("elasticsearch.trace")
        tracer.setLevel(logging.INFO)
        tracer.addHandler(logging.FileHandler(args.es_debug_trace))


def CFG() -> Config:
    return _cfg


_cfg: Optional[Config] = None


def load_config(args):
    global _cfg
    _cfg = Config.load_config(args)
