from abc import ABCMeta, abstractmethod

from elastalert.exceptions import EAException
from elastalert.queries.elasticsearch_query import ElasticsearchAggregationQuery
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType
from elastalert.utils.time import total_seconds, ts_to_dt


class BaseAggregationRule(RuleType, metaclass=ABCMeta):
    def __init__(self, *args):
        super(BaseAggregationRule, self).__init__(*args)
        self.query_factory = QueryFactory(
            ElasticsearchAggregationQuery, self.rule_config, self.add_aggregation_data
        )
        bucket_interval = self.rules.get("bucket_interval")
        if bucket_interval:
            if "seconds" in bucket_interval:
                self.rules["bucket_interval_period"] = (
                    str(bucket_interval["seconds"]) + "s"
                )
            elif "minutes" in bucket_interval:
                self.rules["bucket_interval_period"] = (
                    str(bucket_interval["minutes"]) + "m"
                )
            elif "hours" in bucket_interval:
                self.rules["bucket_interval_period"] = (
                    str(bucket_interval["hours"]) + "h"
                )
            elif "days" in bucket_interval:
                self.rules["bucket_interval_period"] = (
                    str(bucket_interval["days"]) + "d"
                )
            elif "weeks" in bucket_interval:
                self.rules["bucket_interval_period"] = (
                    str(bucket_interval["weeks"]) + "w"
                )
            else:
                raise EAException("Unsupported window size")

            if self.rules.get("use_run_every_query_size"):
                if (
                    total_seconds(self.rules["run_every"])
                    % total_seconds(self.rules["bucket_interval_timedelta"])
                    != 0
                ):
                    raise EAException(
                        "run_every must be evenly divisible by bucket_interval if specified"
                    )
            else:
                if (
                    total_seconds(self.rules["buffer_time"])
                    % total_seconds(self.rules["bucket_interval_timedelta"])
                    != 0
                ):
                    raise EAException(
                        "Buffer_time must be evenly divisible by bucket_interval if specified"
                    )

    @abstractmethod
    def generate_aggregation_query(self):
        pass

    def add_aggregation_data(self, payload):
        for timestamp, payload_data in payload.items():
            if "interval_aggs" in payload_data:
                self.unwrap_interval_buckets(
                    timestamp, None, payload_data["interval_aggs"]["buckets"]
                )
            elif "bucket_aggs" in payload_data:
                self.unwrap_term_buckets(
                    timestamp, payload_data["bucket_aggs"]["buckets"]
                )
            else:
                self.check_matches(timestamp, None, payload_data)

    def unwrap_interval_buckets(self, timestamp, query_key, interval_buckets):
        for interval_data in interval_buckets:
            # Use bucket key here instead of start_time for more accurate match timestamp
            self.check_matches(
                ts_to_dt(interval_data["key_as_string"]), query_key, interval_data
            )

    def unwrap_term_buckets(self, timestamp, term_buckets):
        for term_data in term_buckets:
            if "interval_aggs" in term_data:
                self.unwrap_interval_buckets(
                    timestamp, term_data["key"], term_data["interval_aggs"]["buckets"]
                )
            else:
                self.check_matches(timestamp, term_data["key"], term_data)

    @abstractmethod
    def check_matches(self, timestamp, query_key, aggregation_data):
        pass
