from elastalert.exceptions import EAException
from elastalert.ruletypes.base_aggregation_rule import BaseAggregationRule


class PercentageMatchRule(BaseAggregationRule):
    required_options = frozenset(["match_bucket_filter"])

    def __init__(self, *args):
        super(PercentageMatchRule, self).__init__(*args)
        self.ts_field = self.rules.get("timestamp_field", "@timestamp")
        if "max_percentage" not in self.rules and "min_percentage" not in self.rules:
            raise EAException(
                "PercentageMatchRule must have at least one of either min_percentage or max_percentage"
            )

        self.min_denominator = self.rules.get("min_denominator", 0)
        self.match_bucket_filter = self.rules["match_bucket_filter"]
        self.rules["aggregation_query_element"] = self.generate_aggregation_query()

    def get_match_str(self, match):
        percentage_format_string = self.rules.get("percentage_format_string", None)
        message = (
            "Percentage violation, value: %s (min: %s max : %s) of %s items\n\n"
            % (
                percentage_format_string % (match["percentage"])
                if percentage_format_string
                else match["percentage"],
                self.rules.get("min_percentage"),
                self.rules.get("max_percentage"),
                match["denominator"],
            )
        )
        return message

    def generate_aggregation_query(self):
        return {
            "percentage_match_aggs": {
                "filters": {
                    "other_bucket": True,
                    "filters": {
                        "match_bucket": {"bool": {"must": self.match_bucket_filter}}
                    },
                }
            }
        }

    def check_matches(self, timestamp, query_key, aggregation_data):
        match_bucket_count = aggregation_data["percentage_match_aggs"]["buckets"][
            "match_bucket"
        ]["doc_count"]
        other_bucket_count = aggregation_data["percentage_match_aggs"]["buckets"][
            "_other_"
        ]["doc_count"]

        if match_bucket_count is None or other_bucket_count is None:
            return
        else:
            total_count = other_bucket_count + match_bucket_count
            if total_count == 0 or total_count < self.min_denominator:
                return
            else:
                match_percentage = (
                    (match_bucket_count * 1.0) / (total_count * 1.0) * 100
                )
                if self.percentage_violation(match_percentage):
                    match = {
                        self.rules["timestamp_field"]: timestamp,
                        "percentage": match_percentage,
                        "denominator": total_count,
                    }
                    if query_key is not None:
                        match[self.rules["query_key"]] = query_key
                    self.add_match(match)

    def percentage_violation(self, match_percentage):
        if (
            "max_percentage" in self.rules
            and match_percentage > self.rules["max_percentage"]
        ):
            return True
        if (
            "min_percentage" in self.rules
            and match_percentage < self.rules["min_percentage"]
        ):
            return True
        return False
