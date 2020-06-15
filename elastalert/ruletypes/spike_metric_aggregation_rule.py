from elastalert.exceptions import EAConfigException
from elastalert.queries.elasticsearch_query import ElasticsearchSpikeAggregationQuery
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType
from elastalert.utils import arithmetic
from elastalert.utils.time import pretty_ts


class SpikeMetricAggregationRule(RuleType):

    required_options = frozenset(
        ["metric_agg_key", "metric_agg_type", "spike_height", "spike_type"]
    )
    allowed_aggregations = frozenset(
        ["min", "max", "avg", "sum", "cardinality", "value_count"]
    )
    allowed_ref_aggregations = frozenset(
        ["min", "max", "variance", "std_deviation", "median_absolute_deviation"]
    )
    # TODO median and percentiles

    def __init__(self, rule_config, *args, **kwargs):
        super().__init__(rule_config, *args, **kwargs)
        self.timeframe = self.rule_config["timeframe"]
        self.ts_field = self.rules.get("timestamp_field", "@timestamp")
        self.data_field = "value"

        if self.rule_config["metric_agg_type"] not in self.allowed_aggregations:
            raise EAConfigException(
                "metric_agg_type must be one of %s" % (str(self.allowed_aggregations))
            )
        if (
            self.rule_config.get("metric_ref_agg_type")
            and self.rule_config["metric_ref_agg_type"]
            not in self.allowed_ref_aggregations
        ):
            raise EAConfigException(
                "metric_ref_agg_type must be one of %s"
                % (str(self.allowed_ref_aggregations))
            )

        self.ref_window_count = self.rule_config.get("ref_window_count", 1)
        self.spike_ref_metric = arithmetic.Mapping.get(
            self.rule_config.get("spike_ref_metric", "mean")
        )
        self.spike_ref_metric_args = self.rule_config.get(
            "spike_ref_metric_args", dict()
        )
        self.spike_height_metric = arithmetic.Mapping.get(
            self.rule_config.get("spike_height_metric", "fixed"), lambda ref: ref[0]
        )
        self.spike_height_metric_args = self.rule_config.get(
            "spike_height_metric_args", dict()
        )
        if (
            self.rule_config.get("spike_height_metric", "fixed") != "fixed"
            and self.ref_window_count == 1
        ):
            raise EAConfigException(
                "If spike_height_ref is set to something other than fixed, ref_count must be > 1"
            )

        self.windows = dict()
        self.metric_key = (
            "metric_"
            + self.rule_config["metric_agg_key"]
            + "_"
            + self.rule_config["metric_agg_type"]
        )
        self.metric_ref_key = (
            "metric_ref_"
            + self.rule_config["metric_agg_key"]
            + "_"
            + self.rule_config.get("metric_ref_agg_type", "fixed")
        )

        if self.rule_config.get("metric_ref_agg_type") and self.rule_config[
            "metric_ref_agg_type"
        ] in ["variance", "std_deviation"]:
            self.data_field = self.rule_config["metric_ref_agg_type"]
            self.rule_config["metric_ref_agg_type"] = "extended_stats"

        self.rule_config[
            "aggregation_query_element"
        ] = self.generate_aggregation_query()
        self.garbage_collect_count = 0

    def add_aggregation_data(self, payload):
        for timestamp, payload_data in payload.items():
            if "bucket_aggs" in payload_data:
                self.unwrap_term_buckets(timestamp, payload_data["bucket_aggs"])
            else:
                agg_value = payload_data[self.metric_key]["value"]
                ref_agg_value = payload_data.get(self.metric_ref_key, {}).get(
                    self.data_field, agg_value
                )
                self.windows.setdefault("all", []).append((agg_value, ref_agg_value))

    def unwrap_term_buckets(self, timestamp, term_buckets, qk=[]):
        """
        create separate spike event trackers for each term,
        handle compound query keys
        """
        for term_data in term_buckets["buckets"]:
            qk.append(term_data["key"])

            # handle compound query keys (nested aggregations)
            if term_data.get("bucket_aggs"):
                self.unwrap_term_buckets(timestamp, term_data["bucket_aggs"], qk)
                # reset the query key to consider the proper depth for N > 2
                del qk[-1]
                continue

            qk_str = ",".join(qk)
            agg_value = term_data[self.metric_key]["value"]
            ref_agg_value = term_data.get(self.metric_ref_key, {}).get(
                self.data_field, agg_value
            )
            self.windows.setdefault(qk_str, []).append((agg_value, ref_agg_value))

            # handle unpack of lowest level
            del qk[-1]

    def init_query_factory(self) -> QueryFactory:
        return QueryFactory(
            ElasticsearchSpikeAggregationQuery,
            self.rule_config,
            self.add_aggregation_data,
            self.es,
        )

    def generate_aggregation_query(self) -> dict:
        """"""
        query = {}
        if self.rule_config.get("metric_agg_script"):
            query[self.metric_key] = {
                self.rules["metric_agg_type"]: self.rule_config["metric_agg_script"]
            }
        else:
            query[self.metric_key] = {
                self.rule_config["metric_agg_type"]: {
                    "field": self.rule_config["metric_agg_key"]
                }
            }
        if self.rule_config.get("metric_ref_agg_type"):
            query[self.metric_ref_key] = {
                self.rule_config["metric_ref_agg_type"]: {
                    "field": self.rule_config["metric_agg_key"]
                }
            }
        return query

    def garbage_collect(self, timestamp):
        if self.garbage_collect_count < self.ref_window_count:
            # we don't have all data
            self.garbage_collect_count += 1
        else:
            for qk, window_data in self.windows.items():
                cur = window_data[-1][0]
                refs, ref_aggs = map(list, zip(*window_data[:-1]))
                ref = self.spike_ref_metric(refs, **self.spike_ref_metric_args)
                ref_metric = self.spike_height_metric(
                    ref_aggs, **self.spike_height_metric_args
                )
                if cur < self.rules.get("threshold_cur", 0) or ref < self.rules.get(
                    "threshold_ref", 0
                ):
                    return
                if (
                    self.rule_config.get("spike_height_metric", "fixed") == "fixed"
                    and self.rule_config.get("metric_ref_agg_type") is None
                ):
                    up_ref_value = ref * self.rule_config["spike_height"]
                    down_ref_value = ref / self.rule_config["spike_height"]
                else:
                    up_ref_value = ref + ref_metric * self.rule_config["spike_height"]
                    down_ref_value = ref - (
                        ref_metric * self.rule_config["spike_height"]
                    )
                if (
                    self.rule_config["spike_type"] in ["both", "up"]
                    and cur >= up_ref_value
                ) or (
                    self.rule_config["spike_type"] in ["both", "down"]
                    and cur <= down_ref_value
                ):
                    match = {
                        "spike_count": cur,
                        "reference_count": ref,
                        "reference_metric_value": ref_metric,
                        self.ts_field: timestamp,
                    }
                    self.add_match(match)

            # clear window information
            self.windows = {}
            self.garbage_collect_count = 0

    def get_match_str(self, match):
        """
        Overwrite SpikeRule's message to relate to the aggregation type & field instead of count
        """
        message = "An abnormal {0} of {1} ({2}) occurred around {3}.\n".format(
            self.rules["metric_agg_type"],
            self.rules["metric_agg_key"],
            round(match["spike_count"], 2),
            pretty_ts(match[self.ts_field], self.rules.get("use_local_time")),
        )
        message += "Preceding that time, there was a {0} of {1} of ({2}) within {3}\n\n".format(
            self.rules["metric_agg_type"],
            self.rules["metric_agg_key"],
            round(match["reference_count"], 2),
            self.rules["timeframe"],
        )
        return message
