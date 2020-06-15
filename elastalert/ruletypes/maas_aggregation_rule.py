from elastalert.clients.mlflow_client import MaasClientMapper
from elastalert.queries.elasticsearch_query import ElasticsearchMaasAggregationQuery
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes.base_aggregation_rule import BaseAggregationRule
from elastalert.utils.maas_filter import FilterMapper
from elastalert.utils.time import ts_to_dt


class MaasAggregationRule(BaseAggregationRule):
    """
    Aggregation Rule, which sends aggregated results to an external Model to get anomaly information.
    """

    def init_query_factory(self):
        return QueryFactory(
            ElasticsearchMaasAggregationQuery,
            self.rule_config,
            self.add_aggregation_data,
            self.es,
        )

    def __init__(self, rule_config, *args, **kwargs):
        super(MaasAggregationRule, self).__init__(rule_config, *args)
        self.ts_field = self.rules.get("timestamp_field", "@timestamp")
        self.metric_key = None

        self.rule_config[
            "aggregation_query_element"
        ] = self.generate_aggregation_query()

        maas_config = rule_config.get("maas")
        maas_type = maas_config.get("type")

        filter_condition = maas_config.get("filter_condition")
        filter_value = maas_config.get("filter_value")

        filter_class = FilterMapper.get(maas_config.get("filter"))
        self.data_filter = filter_class(filter_condition, filter_value)
        columns_mapping = [
            {"name": self.ts_field, "map_to": "ds"},
            {"name": "count", "map_to": "y"},
        ]
        if "query_key" in self.rule_config:
            columns_mapping.extend([{"name": self.rules["query_key"], "map_to": "key"}])

        self.client_req_item = []
        self.client = MaasClientMapper.get(maas_type)(
            maas_config.get("endpoint"), columns_mapping
        )

    def generate_aggregation_query(self):
        """ Generate the aggregation query if a metric key and type were supplied  """
        query = {}
        if (
            "metric_agg_key" in self.rule_config
            or "metric_agg_script" in self.rule_config
        ):
            metric_key = (
                "metric_"
                + self.rule_config["metric_agg_key"]
                + "_"
                + self.rule_config["metric_agg_type"]
            )
            if self.rule_config.get("metric_agg_script"):
                query[metric_key] = {
                    self.rules["metric_agg_type"]: self.rule_config["metric_agg_script"]
                }
            else:
                query[metric_key] = {
                    self.rule_config["metric_agg_type"]: {
                        "field": self.rule_config["metric_agg_key"]
                    }
                }
            self.metric_key = metric_key
        return query

    def add_aggregation_data(self, payload):
        """ Adds anomalyous aggregation data, determined by external model  """
        self.client_req_item = []
        super().add_aggregation_data(payload)
        data = self.client_req_item
        maas_response = self.client.send(self.client_req_item)

        matches = [
            data[i]
            for i, resp in enumerate(maas_response)
            if self.data_filter.execute(resp)
        ]
        for match in matches:
            self.add_match(match)

    def check_matches(self, timestamp, query_key, aggregation_data):
        """ Adds all matches to a list, before sending to external Model."""
        if not self.metric_key:
            match = {
                self.ts_field: timestamp,
                "count": aggregation_data["doc_count"],
            }
            if query_key is not None:
                match[self.rules["query_key"]] = query_key

            self.client_req_item.append(match)
        elif "compound_query_key" in self.rules:
            self.check_matches_recursive(
                timestamp,
                query_key,
                aggregation_data,
                self.rules["compound_query_key"],
                dict(),
            )

        else:
            metric_val = aggregation_data[self.metric_key]["value"]
            match = {
                self.ts_field: timestamp,
                "count": metric_val,
            }
            if query_key is not None:
                match[self.rules["query_key"]] = query_key

            self.client_req_item.append(match)

    def check_matches_recursive(
        self, timestamp, query_key, aggregation_data, compound_keys, match_data
    ):
        """
        Recursive execution in case of compound or nested queries to add data for sending to external model.
        """

        if compound_keys:
            match_data[compound_keys[0]] = aggregation_data["key"]
        if "bucket_aggs" in aggregation_data:
            for result in aggregation_data["bucket_aggs"]["buckets"]:
                self.check_matches_recursive(
                    timestamp, query_key, result, compound_keys[1:], match_data.copy(),
                )

        elif "interval_aggs" in aggregation_data:
            for result in aggregation_data["interval_aggs"]["buckets"]:
                timestamp = ts_to_dt(result["key_as_string"])
                self.check_matches_recursive(
                    timestamp, query_key, result, compound_keys[1:], match_data.copy()
                )

        else:
            metric_val = aggregation_data[self.metric_key]["value"]
            match_data[self.ts_field] = timestamp
            match_data["count"] = metric_val

            # add compound key to payload to allow alerts to trigger for every unique occurence
            compound_value = [
                match_data[key] for key in self.rules["compound_query_key"]
            ]
            match_data[self.rules["query_key"]] = ",".join(
                [str(value) for value in compound_value]
            )
            self.client_req_item.append(match_data)

    def garbage_collect(self, timestamp):
        pass
