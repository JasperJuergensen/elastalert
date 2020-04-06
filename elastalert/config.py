import argparse
import datetime
import logging
import logging.config

from elastalert.exceptions import EAConfigException
from envparse import Env
from staticconf.loader import yaml_loader

log = logging.getLogger(__name__)

# Required global (config.yaml) configuration options
required_globals = frozenset(
    ["run_every", "es_host", "es_port", "writeback_index", "buffer_time"]
)

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


def parse_duration(value):
    """Convert ``unit=num`` spec into a ``timedelta`` object."""
    unit, num = value.split("=")
    return datetime.timedelta(**{unit: int(num)})


def parse_args(args) -> argparse.Namespace:
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
    return parser.parse_args(args)


def configure_logging(args, conf):
    # configure logging from config file if provided
    if "logging" in conf:
        # load new logging config
        logging.config.dictConfig(conf["logging"])
    else:
        logging.basicConfig()

    if args.verbose and args.debug:
        log.info("Note: --debug and --verbose flags are set. --debug takes precedent.")

    # re-enable INFO log level on elastalert_logger in verbose/debug mode
    # (but don't touch it if it is already set to INFO or below by config)
    if args.verbose or args.debug:
        if log.level > logging.INFO or log.level == logging.NOTSET:
            logging.getLogger("elastalert").setLevel(logging.INFO)

    if args.debug:
        log.info(
            "Note: In debug mode, alerts will be logged to console but NOT actually sent. To send them but remain verbose, use --verbose instead."
        )
        logging.getLogger("elastalert").setLevel(logging.DEBUG)

    if not args.es_debug and "logging" not in conf:
        logging.getLogger("elasticsearch").setLevel(logging.WARNING)

    if args.es_debug_trace:
        tracer = logging.getLogger("elasticsearch.trace")
        tracer.setLevel(logging.INFO)
        tracer.addHandler(logging.FileHandler(args.es_debug_trace))


def load_config(args) -> dict:
    args = parse_args(args)
    filename = args.config or "config.yaml"
    try:
        conf = yaml_loader(filename)
    except FileNotFoundError:
        raise EAConfigException("Config file '{}' not found".format(filename))
    conf["args"] = args

    # init logging from config and set log levels according to command line options
    configure_logging(args, conf)

    if args.debug:
        conf["debug"] = True
    else:
        conf["debug"] = False

    for env_var, conf_var in env_settings.items():
        val = env(env_var, None)
        if val is not None:
            conf[conf_var] = val

    # Make sure we have all required globals
    if required_globals - frozenset(list(conf.keys())):
        raise EAConfigException(
            "%s must contain %s"
            % (filename, ", ".join(required_globals - frozenset(list(conf.keys()))))
        )

    conf.setdefault("writeback_alias", "elastalert_alerts")
    conf.setdefault("max_query_size", 10000)
    conf.setdefault("scroll_keepalive", "30s")
    conf.setdefault("max_scrolling_count", 0)
    conf.setdefault("disable_rules_on_error", True)
    conf.setdefault("scan_subdirectories", True)
    conf.setdefault("rules_loader", "file")
    conf.setdefault("alert_time_limit", {"days": 2})
    conf.setdefault("old_query_limit", {"weeks": 1})

    # Convert run_every, buffer_time into a timedelta object
    try:
        conf["run_every"] = datetime.timedelta(**conf["run_every"])
        conf["buffer_time"] = datetime.timedelta(**conf["buffer_time"])
        conf["alert_time_limit"] = datetime.timedelta(**conf["alert_time_limit"])
        conf["old_query_limit"] = datetime.timedelta(**conf["old_query_limit"])
    except (KeyError, TypeError) as e:
        raise EAConfigException("Invalid time format used: %s" % e)

    return conf


config = None


def get_config():
    return config


class Config:
    """"""
