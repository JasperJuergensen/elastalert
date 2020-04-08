from elastalert.exceptions import EAException
from elastalert.ruletypes.base_aggregation_rule import BaseAggregationRule
from elastalert.ruletypes.spike_rule import SpikeRule
from elastalert.utils.time import pretty_ts


# TODO there is probably a problem with multiple inheritance
class SpikeMetricAggregationRule(BaseAggregationRule, SpikeRule):
    """ A rule that matches when there is a spike in an aggregated event compared to its reference point """

    required_options = frozenset(
        ["metric_agg_key", "metric_agg_type", "spike_height", "spike_type"]
    )
    allowed_aggregations = frozenset(
        ["min", "max", "avg", "sum", "cardinality", "value_count"]
    )

    def __init__(self, *args):
        # We inherit everything from BaseAggregation and Spike, overwrite only what we need in functions below
        super(SpikeMetricAggregationRule, self).__init__(*args)

        # MetricAgg alert things
        self.metric_key = (
            "metric_"
            + self.rules["metric_agg_key"]
            + "_"
            + self.rules["metric_agg_type"]
        )
        if self.rules["metric_agg_type"] not in self.allowed_aggregations:
            raise EAException(
                "metric_agg_type must be one of %s" % (str(self.allowed_aggregations))
            )

        # Disabling bucket intervals (doesn't make sense in context of spike to split up your time period)
        if self.rules.get("bucket_interval"):
            raise EAException(
                "bucket intervals are not supported for spike aggregation alerts"
            )

        self.rules["aggregation_query_element"] = self.generate_aggregation_query()

    def generate_aggregation_query(self):
        """Lifted from MetricAggregationRule, added support for scripted fields"""
        if self.rules.get("metric_agg_script"):
            return {
                self.metric_key: {
                    self.rules["metric_agg_type"]: self.rules["metric_agg_script"]
                }
            }
        return {
            self.metric_key: {
                self.rules["metric_agg_type"]: {"field": self.rules["metric_agg_key"]}
            }
        }

    def add_aggregation_data(self, payload):
        """
        BaseAggregationRule.add_aggregation_data unpacks our results and runs checks directly against hardcoded cutoffs.
        We instead want to use all of our SpikeRule.handle_event inherited logic (current/reference) from
        the aggregation's "value" key to determine spikes from aggregations
        """
        for timestamp, payload_data in payload.items():
            if "bucket_aggs" in payload_data:
                self.unwrap_term_buckets(timestamp, payload_data["bucket_aggs"])
            else:
                # no time / term split, just focus on the agg
                event = {self.ts_field: timestamp}
                agg_value = payload_data[self.metric_key]["value"]
                self.handle_event(event, agg_value, "all")
        return

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
            event = {self.ts_field: timestamp, self.rules["query_key"]: qk_str}
            # pass to SpikeRule's tracker
            self.handle_event(event, agg_value, qk_str)

            # handle unpack of lowest level
            del qk[-1]
        return

    def get_match_str(self, match):
        """
        Overwrite SpikeRule's message to relate to the aggregation type & field instead of count
        """
        message = "An abnormal {0} of {1} ({2}) occurred around {3}.\n".format(
            self.rules["metric_agg_type"],
            self.rules["metric_agg_key"],
            round(match["spike_count"], 2),
            pretty_ts(
                match[self.rules["timestamp_field"]], self.rules.get("use_local_time")
            ),
        )
        message += "Preceding that time, there was a {0} of {1} of ({2}) within {3}\n\n".format(
            self.rules["metric_agg_type"],
            self.rules["metric_agg_key"],
            round(match["reference_count"], 2),
            self.rules["timeframe"],
        )
        return message

    def check_matches(self, timestamp, query_key, aggregation_data):
        raise NotImplementedError
