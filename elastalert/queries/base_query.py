from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta
from typing import Tuple


class BaseQuery(metaclass=ABCMeta):
    """"""

    def __init__(self, rule_config: dict, callback: callable, persistent: dict):
        """
        Initializes a query

        :param global_config: The global configuration
        :param rule_config: The rule configuration
        :param callback: The callback from the ruletype instance where the data will be returned
        """
        self.rule_config = rule_config
        self.callback = callback
        self.persistent = persistent
        self.query = None
        self.build_query()

    def run(self, endtime: datetime) -> Tuple[datetime, datetime, int]:
        """
        Runs the query. This includes the query execution and the callback.

        This function raises a EARuntimeException if there is a problem so the rule execution
        cannot be continued

        :param endtime: End time for the query time range

        :return: A tuple with (starttime, endtime, hits)
        """
        if self.rule_config.get("initial_starttime"):
            starttime = self.rule_config["initial_starttime"]
        else:
            starttime = self.set_starttime(endtime)
        cumulative_hits = 0
        segment_size = self.get_segment_size()
        tmp_endtime = starttime
        while endtime - tmp_endtime > segment_size:
            tmp_endtime += segment_size
            cumulative_hits += self.run_query(starttime, tmp_endtime)
            starttime = tmp_endtime
            self.rule_config["type"].garbage_collect(tmp_endtime)
        cumulative_hits += self.run_query(starttime, endtime)
        self.rule_config["type"].garbage_collect(endtime)
        return starttime, endtime, cumulative_hits

    @abstractmethod
    def get_segment_size(self) -> timedelta:
        """
        Calculates a segment size to mimick the query size

        :return: the segment size
        """

    @abstractmethod
    def set_starttime(self, endtime):
        """
        Calculates the starttime for the current query

        :param starttime: the old starttime (can be None)
        :param endtime: the endtime (can be None)
        :return: the starttime
        """

    @abstractmethod
    def build_query(self):
        """Builds the query"""

    @abstractmethod
    def run_query(self, starttime, endtime) -> int:
        """
        Runs the query against the datasource.
        This function has to call the callback to pass the data to the rule.

        :param starttime:
        :param endtime:
        """
