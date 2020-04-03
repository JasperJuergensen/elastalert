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


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Config(metaclass=Singleton):
    def __init__(self, args=None, defaults=None, overwrites=None):
        super().__init__()
        filename = args.config or "config.yaml"
        try:
            conf = yaml_loader(filename)
        except FileNotFoundError:
            raise EAConfigException("Config file '{}' not found".format(filename))

        # init logging from config and set log levels according to command line options
        self.configure_logging(args, conf)

        if args.debug:
            conf["debug"] = True
        else:
            conf["debug"] = False

        for env_var, conf_var in env_settings.items():
            val = env(env_var, None)
            if val is not None:
                conf[conf_var] = val

        if defaults is not None:
            for key, value in defaults.items():
                if key not in conf:
                    conf[key] = value

        if overwrites is not None:
            for key, value in overwrites.items():
                conf[key] = value

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

        self.conf = conf

    def configure_logging(self, args, conf):
        # configure logging from config file if provided
        if "logging" in conf:
            # load new logging config
            logging.config.dictConfig(conf["logging"])

        if args.verbose and args.debug:
            log.info(
                "Note: --debug and --verbose flags are set. --debug takes precedent."
            )

        # re-enable INFO log level on elastalert_logger in verbose/debug mode
        # (but don't touch it if it is already set to INFO or below by config)
        if args.verbose or args.debug:
            if log.level > logging.INFO or log.level == logging.NOTSET:
                logging.getLogger("elastalert").setLevel(logging.DEBUG)

        if args.debug:
            log.info(
                """Note: In debug mode, alerts will be logged to console but NOT actually sent.
                To send them but remain verbose, use --verbose instead."""
            )

        if not args.es_debug and "logging" not in conf:
            logging.getLogger("elasticsearch").setLevel(logging.WARNING)

        if args.es_debug_trace:
            tracer = logging.getLogger("elasticsearch.trace")
            tracer.setLevel(logging.INFO)
            tracer.addHandler(logging.FileHandler(args.es_debug_trace))
