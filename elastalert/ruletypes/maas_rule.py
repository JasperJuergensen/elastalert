from typing import List

from elastalert.clients.mlflow_client import MaasClientMapper
from elastalert.queries.elasticsearch_query import ElasticsearchQuery
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType
from elastalert.utils.maas_filter import FilterMapper


class MaasRule(RuleType):
    """ Simple Maas-Rule that sends queried data to an external Model"""

    def init_query_factory(self) -> QueryFactory:
        return QueryFactory(ElasticsearchQuery, self.rule_config, self.add_data)

    def __init__(self, rule_config, *args, **kwargs):
        super().__init__(rule_config, *args, **kwargs)

        self.ts_field = rule_config.get("timestamp_field", "@timestamp")

        maas_config = rule_config.get("maas")
        maas_type = maas_config.get("type")

        filter_condition = maas_config.get("filter_condition")
        filter_value = maas_config.get("filter_value")

        filter_class = FilterMapper.get(maas_config.get("filter"))
        self.data_filter = filter_class(filter_condition, filter_value)
        self.client = MaasClientMapper.get(maas_type)(
            maas_config.get("endpoint"), maas_config.get("columns_mapping")
        )

    def add_data(self, data: List[dict]) -> None:
        maas_response = self.client.send(data)

        matches = [
            data[i]
            for i, resp in enumerate(maas_response)
            if self.data_filter.execute(resp)
        ]
        for match in matches:
            self.add_match(match)
