from elastalert.queries.elasticsearch_query import ElasticsearchQuery
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType


class AnyRule(RuleType):
    """ A rule that will match on any input data """

    def init_query_factory(self):
        return QueryFactory(
            ElasticsearchQuery, self.rule_config, self.add_data
        )

    def __init__(self, rule_config, args = None):
        super().__init__(rule_config)

    def add_data(self, data):
        for datum in data:
            self.add_match(datum)

