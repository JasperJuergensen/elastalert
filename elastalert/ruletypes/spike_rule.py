import datetime
from typing import Dict, List

from elastalert.exceptions import EAConfigException
from elastalert.queries.elasticsearch_query import (
    ElasticsearchQuery,
    ElasticsearchSpikeCountQuery,
    ElasticsearchSpikeTermQuery,
)
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType
from elastalert.utils import arithmetic
from elastalert.utils.event_window import CountEventWindow
from elastalert.utils.time import pretty_ts
from elastalert.utils.util import hashable, lookup_es_key, new_get_event_ts


class SpikeRule(RuleType):
    def __init__(self, rule_config, *args, **kwargs):
        super().__init__(rule_config, *args, **kwargs)
        self.ts_field = self.rules.get("timestamp_field", "@timestamp")
        self.ref_window_filled_once = False
        self.get_ts = new_get_event_ts(self.ts_field)

        self.timeframe = self.rule_config["timeframe"]
        self.gap_timeframe = self.rule_config.get(
            "gap_timeframe", datetime.timedelta(seconds=0)
        )

        self.ref_window_count = self.rule_config.get("ref_window_count", 1)
        self.spike_ref_metric = arithmetic.Mapping.get(
            self.rule_config.get("spike_ref_metric", "mean")
        )
        self.spike_ref_metric_args = self.rule_config.get(
            "spike_ref_metric_args", dict()
        )
        self.spike_height_metric = arithmetic.Mapping.get(
            self.rule_config.get("spike_height_metric", "fixed"), lambda ref: 1
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
        self.first_event = dict()
        self.skip_checks = dict()

    def init_query_factory(self) -> QueryFactory:
        if self.rule_config.get("use_count_query"):
            return QueryFactory(
                ElasticsearchSpikeCountQuery, self.rule_config, self.add_count_data
            )
        elif self.rule_config.get("use_terms_query"):
            return QueryFactory(
                ElasticsearchSpikeTermQuery, self.rule_config, self.add_terms_data
            )
        else:
            return QueryFactory(ElasticsearchQuery, self.rule_config, self.add_data)

    def garbage_collect(self, timestamp):
        for qk in list(self.windows.keys()):
            # If we havn't seen this key in a long time, forget it
            if qk != "all":
                for window in self.windows[qk]:
                    if window.count() != 0:
                        break
                else:
                    self.windows.pop(qk)
                    continue
            for window in self.windows[qk]:
                # adds a dummy event so that the duration is until now and clears old events
                window.data.add({self.ts_field: timestamp})
                window.clean_old_events()
                del window.data[-1]

    def init_windows(self, qk: str):
        """
        Initializes the event windows for a query key
        :param qk: The query key
        """
        self.windows[qk] = [CountEventWindow(self.timeframe, get_timestamp=self.get_ts)]
        for i in range(self.ref_window_count - 1):
            self.windows[qk].append(
                CountEventWindow(
                    self.timeframe,
                    self.windows[qk][-1].append,
                    get_timestamp=self.get_ts,
                )
            )
        self.windows[qk].append(
            CountEventWindow(
                self.gap_timeframe,
                self.windows[qk][-1].append,
                get_timestamp=self.get_ts,
            )
        )
        self.windows[qk].append(
            CountEventWindow(
                self.timeframe, self.windows[qk][-1].append, get_timestamp=self.get_ts
            )
        )

    def clear_windows(self, qk: str, event: dict):
        # Reset the state and prevent alerts until windows filled again
        for window in self.windows[qk][:-2]:
            window.clear()
        self.first_event.pop(qk)
        self.skip_checks[qk] = (
            lookup_es_key(event, self.ts_field)
            + (self.timeframe * (self.ref_window_count + 1))
            + self.gap_timeframe
        )

    def handle_event(self, event: dict, count: int, qk: str = "all"):
        self.first_event.setdefault(qk, event)
        if qk not in self.windows:
            self.init_windows(qk)
        self.windows[qk][-1].append((event, count))
        # Don't alert if ref window has not yet been filled for this key AND
        if (
            lookup_es_key(event, self.ts_field) - self.first_event[qk][self.ts_field]
            < (self.timeframe * (self.ref_window_count + 1)) + self.gap_timeframe
        ):
            # ElastAlert has not been running long enough for any alerts OR
            if not self.ref_window_filled_once:
                return
            # This rule is not using alert_on_new_data (with query_key) OR
            if not (
                self.rules.get("query_key") and self.rules.get("alert_on_new_data")
            ):
                return
            # An alert for this qk has recently fired
            if (
                qk in self.skip_checks
                and lookup_es_key(event, self.ts_field) < self.skip_checks[qk]
            ):
                return
        else:
            self.ref_window_filled_once = True
        self.find_matches(qk)

    def find_matches(self, qk: str):
        cur = self.windows[qk][-1].count()
        ref_data = [
            self.windows[qk][i].count() for i in range(len(self.windows[qk]) - 2)
        ]
        ref = self.spike_ref_metric(ref_data, **self.spike_ref_metric_args)
        ref_metric = self.spike_height_metric(ref_data, **self.spike_height_metric_args)
        if cur < self.rules.get("threshold_cur", 0) or ref < self.rules.get(
            "threshold_ref", 0
        ):
            return
        if self.rule_config.get("spike_height_metric", "fixed") == "fixed":
            up_ref_value = ref * self.rule_config["spike_height"]
            down_ref_value = ref / self.rule_config["spike_height"]
        else:
            up_ref_value = ref + ref_metric * self.rule_config["spike_height"]
            down_ref_value = ref - (ref_metric * self.rule_config["spike_height"])

        if (
            self.rule_config["spike_type"] in ["both", "up"] and cur >= up_ref_value
        ) or (
            self.rule_config["spike_type"] in ["both", "down"] and cur <= down_ref_value
        ):
            extra_info = {
                "spike_count": cur,
                "reference_count": ref,
                "reference_metric_value": ref_metric,
            }
            match = dict(
                list(self.windows[qk][-1].data[0][0].items()) + list(extra_info.items())
            )
            self.add_match(match)
            self.clear_windows(qk, match)

    def get_match_str(self, match):
        message = "An abnormal number (%d) of events occurred around %s.\n" % (
            match["spike_count"],
            pretty_ts(
                match[self.rules["timestamp_field"]], self.rules.get("use_local_time")
            ),
        )
        message += "Preceding that time, there were only %d events within %s\n\n" % (
            match["reference_count"],
            self.rules["timeframe"],
        )
        return message

    def add_data(self, data: List[dict]):
        for event in data:
            qk = self.rule_config.get("query_key", "all")
            if qk != "all":
                qk = hashable(lookup_es_key(event, qk))
                if qk is None:
                    qk = "other"
            self.handle_event(event, 1, qk)

    def add_count_data(self, counts: Dict[datetime.datetime, int]):
        for ts, count in counts.items():
            self.handle_event({self.ts_field: ts}, count)

    def add_terms_data(self, terms: Dict[datetime.datetime, List[dict]]):
        for timestamp, buckets in terms.items():
            for bucket in buckets:
                count = bucket["doc_count"]
                event = {
                    self.ts_field: timestamp,
                    self.rule_config["query_key"]: bucket["key"],
                }
                key = bucket["key"]
                self.handle_event(event, count, key)
