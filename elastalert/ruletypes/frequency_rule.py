from elastalert.exceptions import EAException
from elastalert.queries.elasticsearch_query import (
    ElasticsearchCountQuery,
    ElasticsearchQuery,
    ElasticsearchTermQuery,
)
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType
from elastalert.utils.event_window import CountEventWindow
from elastalert.utils.time import dt_to_ts, pretty_ts, ts_to_dt
from elastalert.utils.util import hashable, lookup_es_key, new_get_event_ts


class FrequencyRule(RuleType):
    """ A rule that matches if num_events number of events occur within a timeframe """

    required_options = frozenset(["num_events", "timeframe"])

    def init_query_factory(self):
        query_class = ElasticsearchQuery
        callback = self.add_data
        if self.rule_config.get("use_count_query"):
            query_class = ElasticsearchCountQuery
            callback = self.add_count_data
        elif self.rule_config.get("use_terms_query"):
            query_class = ElasticsearchTermQuery
            callback = self.add_terms_data
        return QueryFactory(query_class, self.rule_config, callback, self.es)

    def __init__(self, *args, **kwargs):
        super(FrequencyRule, self).__init__(*args, **kwargs)
        self.ts_field = self.rules.get("timestamp_field", "@timestamp")
        self.get_ts = new_get_event_ts(self.ts_field)
        self.attach_related = self.rules.get("attach_related", False)

    def add_count_data(self, data):
        """ Add count data to the rule. Data should be of the form {ts: count}. """
        if len(data) > 1:
            raise EAException("add_count_data can only accept one count at a time")

        ((ts, count),) = list(data.items())

        event = ({self.ts_field: ts}, count)
        self.occurrences.setdefault(
            "all", CountEventWindow(self.rules["timeframe"], get_timestamp=self.get_ts)
        ).append(event)
        self.check_for_match("all")

    def add_terms_data(self, terms):
        for timestamp, buckets in terms.items():
            for bucket in buckets:
                event = (
                    {self.ts_field: timestamp, self.rules["query_key"]: bucket["key"]},
                    bucket["doc_count"],
                )
                self.occurrences.setdefault(
                    bucket["key"],
                    CountEventWindow(
                        self.rules["timeframe"], get_timestamp=self.get_ts
                    ),
                ).append(event)
                self.check_for_match(bucket["key"])

    def add_data(self, data):
        if "query_key" in self.rules:
            qk = self.rules["query_key"]
        else:
            qk = None

        for event in data:
            if qk:
                key = hashable(lookup_es_key(event, qk))
            else:
                # If no query_key, we use the key 'all' for all events
                key = "all"

            # Store the timestamps of recent occurrences, per key
            self.occurrences.setdefault(
                key,
                CountEventWindow(self.rules["timeframe"], get_timestamp=self.get_ts),
            ).append((event, 1))
            self.check_for_match(key, end=False)

        # We call this multiple times with the 'end' parameter because subclasses
        # may or may not want to check while only partial data has been added
        if key in self.occurrences:  # could have been emptied by previous check
            self.check_for_match(key, end=True)

    def check_for_match(self, key, end=False):
        # Match if, after removing old events, we hit num_events.
        # the 'end' parameter depends on whether this was called from the
        # middle or end of an add_data call and is used in subclasses
        if self.occurrences[key].count() >= self.rules["num_events"]:
            event = self.occurrences[key].data[-1][0]
            if self.attach_related:
                event["related_events"] = [
                    data[0] for data in self.occurrences[key].data[:-1]
                ]
            self.add_match(event)
            self.occurrences.pop(key)

    def garbage_collect(self, timestamp):
        """ Remove all occurrence data that is beyond the timeframe away """
        stale_keys = []
        for key, window in self.occurrences.items():
            if (
                timestamp - lookup_es_key(window.data[-1][0], self.ts_field)
                > self.rules["timeframe"]
            ):
                stale_keys.append(key)
        list(map(self.occurrences.pop, stale_keys))

    def get_match_str(self, match):
        lt = self.rules.get("use_local_time")
        match_ts = lookup_es_key(match, self.ts_field)
        starttime = pretty_ts(
            dt_to_ts(ts_to_dt(match_ts) - self.rules["timeframe"]), lt
        )
        endtime = pretty_ts(match_ts, lt)
        message = "At least %d events occurred between %s and %s\n\n" % (
            self.rules["num_events"],
            starttime,
            endtime,
        )
        return message
