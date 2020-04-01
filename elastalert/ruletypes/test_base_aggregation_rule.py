from elastalert.ruletypes.base_aggregation_rule import BaseAggregationRule


class TestBaseAggregationRule(BaseAggregationRule):
    def generate_aggregation_query(self):
        pass

    def check_matches(self, timestamp, query_key, aggregation_data):
        pass
