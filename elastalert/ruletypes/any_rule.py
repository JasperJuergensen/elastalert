from elastalert.queries.elasticsearch_query import ElasticsearchQuery
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType


class AnyRule(RuleType):
    """ A rule that will match on any input data """

    def init_query_factory(self):
        return QueryFactory(
            ElasticsearchQuery, self.rule_config, self.add_data, self.es
        )

    def add_data(self, data):
        for datum in data:
            self.add_match(datum)
