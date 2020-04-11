import copy
from abc import ABCMeta

from deprecated import deprecated
from elastalert.rule import Rule
from elastalert.utils.time import dt_to_ts


class RuleType(Rule, metaclass=ABCMeta):
    """ The base class for a rule type.
    The class must implement add_data and add any matches to self.matches.

    :param rules: A rule configuration.
    """

    required_options = frozenset()

    def __init__(self, rule_config, *args, **kwargs):
        super().__init__(rule_config, *args, **kwargs)
        self.rules = self.rule_config
        self.occurrences = {}
        self.rules["category"] = self.rules.get("category", "")
        self.rules["description"] = self.rules.get("description", "")
        self.rules["owner"] = self.rules.get("owner", "")
        self.rules["priority"] = self.rules.get("priority", "2")

    @deprecated
    def add_data(self, data):
        """ The function that the ElastAlert client calls with results from ES.
        Data is a list of dictionaries, from Elasticsearch.

        :param data: A list of events, each of which is a dictionary of terms.
        """
        raise NotImplementedError()

    def add_match(self, event):
        """ This function is called on all matching events. Rules use it to add
        extra information about the context of a match. Event is a dictionary
        containing terms directly from Elasticsearch and alerts will report
        all of the information.

        :param event: The matching event, a dictionary of terms.
        """
        # Convert datetime's back to timestamps
        ts = self.rules.get("timestamp_field")
        if ts in event:
            event[ts] = dt_to_ts(event[ts])

        self.matches.append(copy.deepcopy(event))

    def get_match_str(self, match):
        """ Returns a string that gives more context about a match.

        :param match: The matching event, a dictionary of terms.
        :return: A user facing string describing the match.
        """
        return ""

    @deprecated
    def add_count_data(self, counts):
        """ Gets called when a rule has use_count_query set to True. Called to add data from querying to the rule.

        :param counts: A dictionary mapping timestamps to hit counts.
        """
        raise NotImplementedError()

    @deprecated
    def add_terms_data(self, terms):
        """ Gets called when a rule has use_terms_query set to True.

        :param terms: A list of buckets with a key, corresponding to query_key, and the count """
        raise NotImplementedError()

    @deprecated
    def add_aggregation_data(self, payload):
        """ Gets called when a rule has use_terms_query set to True.
        :param terms: A list of buckets with a key, corresponding to query_key, and the count """
        raise NotImplementedError()
