from abc import ABCMeta, abstractmethod


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
        self.build_query()

    def run(self, starttime=None, endtime=None):
        """
        Runs the query. This includes the query execution and the callback.

        This function raises a EARuntimeException if there is a problem so the rule execution
        cannot be continued

        :param starttime: Start time for the query time range
        :param endtime: End time for the query time range
        """
        self.run_query(starttime, endtime)

    @abstractmethod
    def build_query(self):
        """Builds the query"""

    @abstractmethod
    def run_query(self, starttime, endtime):
        """
        Runs the query against the datasource.
        This function has to call the callback to pass the data to the rule.

        :param starttime:
        :param endtime:
        """
