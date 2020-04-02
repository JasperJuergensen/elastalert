import logging
import time

from elastalert.utils.time import ts_now

log = logging.getLogger(__name__)


class Rule:
    """"""

    def __init__(self, rule_config):
        """"""
        self.rule_config = rule_config

    def init_rule(self):
        """TODO"""

    def run_rule(self):
        """"""
        run_start = time.time()
        starttime = "TODO"  # TODO
        endtime = "TODO"  # TODO
        self.query_factory.get_query_instance().run(starttime, endtime)
        time_taken = time.time() - run_start
        body = {
            "rule_name": self.rule_config["name"],
            "endtime": "TODO",  # TODO
            "starttime": "TODO",  # TODO
            "matches": 0,  # TODO
            "hits": 0,  # TODO
            "@timestamp": ts_now(),
            "time_taken": time_taken,
        }
        log.debug(body)
        # TODO writeback
