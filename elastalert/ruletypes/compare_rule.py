from abc import ABCMeta, abstractmethod

from elastalert.queries.elasticsearch_query import ElasticsearchQuery
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType


class CompareRule(RuleType, metaclass=ABCMeta):
    """ A base class for matching a specific term by passing it to a compare function """

    def init_query_factory(self):
        return QueryFactory(
            ElasticsearchQuery, self.rule_config, self.add_data, self.es
        )

    required_options = frozenset(["compound_compare_key"])

    def expand_entries(self, list_type):
        """ Expand entries specified in files using the '!file' directive, if there are
        any, then add everything to a set.
        """
        entries_set = set()
        for entry in self.rules[list_type]:
            if entry.startswith("!file"):  # - "!file /path/to/list"
                filename = entry.split()[1]
                with open(filename, "r") as f:
                    for line in f:
                        entries_set.add(line.rstrip())
            else:
                entries_set.add(entry)
        self.rules[list_type] = entries_set

    @abstractmethod
    def compare(self, event):
        """ An event is a match if this returns true """
        pass

    def add_data(self, data):
        # If compare returns true, add it as a match
        for event in data:
            if self.compare(event):
                self.add_match(event)
