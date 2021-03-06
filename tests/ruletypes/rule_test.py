import copy
import datetime
import unittest

import mock
import pytest
import requests
from elastalert.ruletypes import (
    AnyRule,
    BlacklistRule,
    CardinalityRule,
    ChangeRule,
    FlatlineRule,
    FrequencyRule,
    MaasAggregationRule,
    MaasRule,
    MetricAggregationRule,
    NewTermsRule,
    SpikeMetricAggregationRule,
    SpikeRule,
    WhitelistRule,
)
from elastalert.ruletypes.correlation_rule import CorrelationRule
from elastalert.ruletypes.test_base_aggregation_rule import TestBaseAggregationRule
from elastalert.utils.event_window import EventWindow
from elastalert.utils.time import dt_to_ts, ts_to_dt
from elastalert.utils.util import EAException, ts_now


def hits(size, **kwargs):
    ret = []
    for n in range(size):
        ts = ts_to_dt("2014-09-26T12:%s:%sZ" % (n / 60, n % 60))
        n += 1
        event = create_event(ts, **kwargs)
        ret.append(event)
    return ret


def create_event(timestamp, timestamp_field="@timestamp", **kwargs):
    event = {timestamp_field: timestamp}
    event.update(**kwargs)
    return event


def create_bucket_aggregation(agg_name, buckets):
    return {agg_name: {"buckets": buckets}}


def create_percentage_match_agg(match_count, other_count):
    return create_bucket_aggregation(
        "percentage_match_aggs",
        {
            "match_bucket": {"doc_count": match_count},
            "_other_": {"doc_count": other_count},
        },
    )


def assert_matches_have(matches, terms):
    assert len(matches) == len(terms)
    for match, term in zip(matches, terms):
        assert term[0] in match
        assert match[term[0]] == term[1]
        if len(term) > 2:
            assert match[term[2]] == term[3]


@pytest.fixture(scope="function")
def ea_cls(ea, request):
    request.cls.ea = ea


@pytest.mark.usefixtures("ea_cls")
class TermsTest(unittest.TestCase):
    def test_new_term(self):
        rules = {
            "fields": ["a", "b"],
            "timestamp_field": "@timestamp",
            "es_host": "example.com",
            "es_port": 10,
            "index": "logstash",
            "ts_to_dt": ts_to_dt,
            "dt_to_ts": dt_to_ts,
        }
        mock_res = {
            "aggregations": {
                "filtered": {
                    "values": {
                        "buckets": [
                            {"key": "key1", "doc_count": 1},
                            {"key": "key2", "doc_count": 5},
                        ]
                    }
                }
            }
        }
        self.ea.rule_es.search.return_value = mock_res
        self.ea.rule_es.info.return_value = {"version": {"number": "2.x.x"}}
        call_args = []

        # search is called with a mutable dict containing timestamps, this is
        # required to test
        def record_args(*args, **kwargs):
            call_args.append((copy.deepcopy(args), copy.deepcopy(kwargs)))
            return mock_res

        self.ea.rule_es.search.side_effect = record_args
        rule = NewTermsRule(rules, es=self.ea.rule_es)

        # 30 day default range, 1 day default step, times 2 fields
        assert rule.es.search.call_count == 60

        # Assert that all calls have the proper ordering of time ranges
        old_ts = "2010-01-01T00:00:00Z"
        old_field = ""
        for call in call_args:
            field = call[1]["body"]["aggs"]["filtered"]["aggs"]["values"]["terms"][
                "field"
            ]
            if old_field != field:
                old_field = field
                old_ts = "2010-01-01T00:00:00Z"
            gte = call[1]["body"]["aggs"]["filtered"]["filter"]["bool"]["must"][0][
                "range"
            ]["@timestamp"]["gte"]
            assert gte > old_ts
            lt = call[1]["body"]["aggs"]["filtered"]["filter"]["bool"]["must"][0][
                "range"
            ]["@timestamp"]["lt"]
            assert lt > gte
            old_ts = gte

        # Key1 and key2 shouldn't cause a match
        rule.add_data([{"@timestamp": ts_now(), "a": "key1", "b": "key2"}])
        assert rule.matches == []

        # Neither will missing values
        rule.add_data([{"@timestamp": ts_now(), "a": "key2"}])
        assert rule.matches == []

        # Key3 causes an alert for field b
        rule.add_data([{"@timestamp": ts_now(), "a": "key2", "b": "key3"}])
        assert len(rule.matches) == 1
        assert rule.matches[0]["new_field"] == "b"
        assert rule.matches[0]["b"] == "key3"
        rule.matches = []

        # Key3 doesn't cause another alert for field b
        rule.add_data([{"@timestamp": ts_now(), "a": "key2", "b": "key3"}])
        assert rule.matches == []

        # Missing_field
        rules["alert_on_missing_field"] = True
        self.ea.rule_es.return_value = mock.Mock()
        self.ea.rule_es.search.return_value = mock_res
        self.ea.rule_es.info.return_value = {"version": {"number": "2.x.x"}}
        rule = NewTermsRule(rules, es=self.ea.rule_es)
        rule.add_data([{"@timestamp": ts_now(), "a": "key2"}])
        assert len(rule.matches) == 1
        assert rule.matches[0]["missing_field"] == "b"

    def test_new_term_nested_field(self):

        rules = {
            "fields": ["a", "b.c"],
            "timestamp_field": "@timestamp",
            "es_host": "example.com",
            "es_port": 10,
            "index": "logstash",
            "ts_to_dt": ts_to_dt,
            "dt_to_ts": dt_to_ts,
        }
        mock_res = {
            "aggregations": {
                "filtered": {
                    "values": {
                        "buckets": [
                            {"key": "key1", "doc_count": 1},
                            {"key": "key2", "doc_count": 5},
                        ]
                    }
                }
            }
        }
        self.ea.rule_es.search.return_value = mock_res
        self.ea.rule_es.info.return_value = {"version": {"number": "2.x.x"}}
        rule = NewTermsRule(rules, es=self.ea.rule_es)
        assert rule.es.search.call_count == 60

        # Key3 causes an alert for nested field b.c
        rule.add_data([{"@timestamp": ts_now(), "b": {"c": "key3"}}])
        assert len(rule.matches) == 1
        assert rule.matches[0]["new_field"] == "b.c"
        assert rule.matches[0]["b"]["c"] == "key3"
        rule.matches = []

    def test_new_term_with_terms(self):
        rules = {
            "fields": ["a"],
            "timestamp_field": "@timestamp",
            "es_host": "example.com",
            "es_port": 10,
            "index": "logstash",
            "query_key": "a",
            "window_step_size": {"days": 2},
            "ts_to_dt": ts_to_dt,
            "dt_to_ts": dt_to_ts,
        }
        mock_res = {
            "aggregations": {
                "filtered": {
                    "values": {
                        "buckets": [
                            {"key": "key1", "doc_count": 1},
                            {"key": "key2", "doc_count": 5},
                        ]
                    }
                }
            }
        }
        self.ea.rule_es.search.return_value = mock_res
        self.ea.rule_es.info.return_value = {"version": {"number": "2.x.x"}}
        rule = NewTermsRule(rules, es=self.ea.rule_es)

        # Only 15 queries because of custom step size
        assert rule.es.search.call_count == 15

        # Key1 and key2 shouldn't cause a match
        terms = {
            ts_now(): [{"key": "key1", "doc_count": 1}, {"key": "key2", "doc_count": 1}]
        }
        rule.add_terms_data(terms)
        assert rule.matches == []

        # Key3 causes an alert for field a
        terms = {ts_now(): [{"key": "key3", "doc_count": 1}]}
        rule.add_terms_data(terms)
        assert len(rule.matches) == 1
        assert rule.matches[0]["new_field"] == "a"
        assert rule.matches[0]["a"] == "key3"
        rule.matches = []

        # Key3 doesn't cause another alert
        terms = {ts_now(): [{"key": "key3", "doc_count": 1}]}
        rule.add_terms_data(terms)
        assert rule.matches == []

    def test_new_term_with_composite_fields(self):
        rules = {
            "fields": [["a", "b", "c"], ["d", "e.f"]],
            "timestamp_field": "@timestamp",
            "es_host": "example.com",
            "es_port": 10,
            "index": "logstash",
            "ts_to_dt": ts_to_dt,
            "dt_to_ts": dt_to_ts,
        }

        mock_res = {
            "aggregations": {
                "filtered": {
                    "values": {
                        "buckets": [
                            {
                                "key": "key1",
                                "doc_count": 5,
                                "values": {
                                    "buckets": [
                                        {
                                            "key": "key2",
                                            "doc_count": 5,
                                            "values": {
                                                "buckets": [
                                                    {"key": "key3", "doc_count": 3},
                                                    {"key": "key4", "doc_count": 2},
                                                ]
                                            },
                                        }
                                    ]
                                },
                            }
                        ]
                    }
                }
            }
        }

        self.ea.rule_es.search.return_value = mock_res
        self.ea.rule_es.info.return_value = {"version": {"number": "2.x.x"}}
        rule = NewTermsRule(rules, es=self.ea.rule_es)

        assert rule.es.search.call_count == 60

        # key3 already exists, and thus shouldn't cause a match
        rule.add_data([{"@timestamp": ts_now(), "a": "key1", "b": "key2", "c": "key3"}])
        assert rule.matches == []

        # key5 causes an alert for composite field [a, b, c]
        rule.add_data([{"@timestamp": ts_now(), "a": "key1", "b": "key2", "c": "key5"}])
        assert len(rule.matches) == 1
        assert rule.matches[0]["new_field"] == ("a", "b", "c")
        assert rule.matches[0]["a"] == "key1"
        assert rule.matches[0]["b"] == "key2"
        assert rule.matches[0]["c"] == "key5"
        rule.matches = []

        # New values in other fields that are not part of the composite key should
        # not cause an alert
        rule.add_data(
            [
                {
                    "@timestamp": ts_now(),
                    "a": "key1",
                    "b": "key2",
                    "c": "key4",
                    "d": "unrelated_value",
                }
            ]
        )
        assert len(rule.matches) == 0
        rule.matches = []

        # Verify nested fields work properly
        # Key6 causes an alert for nested field e.f
        rule.add_data([{"@timestamp": ts_now(), "d": "key4", "e": {"f": "key6"}}])
        assert len(rule.matches) == 1
        assert rule.matches[0]["new_field"] == ("d", "e.f")
        assert rule.matches[0]["d"] == "key4"
        assert rule.matches[0]["e"]["f"] == "key6"
        rule.matches = []

        # Missing_fields
        rules["alert_on_missing_field"] = True
        self.ea.rule_es.search.return_value = mock_res
        self.ea.rule_es.info.return_value = {"version": {"number": "2.x.x"}}
        rule = NewTermsRule(rules, es=self.ea.rule_es)
        rule.add_data([{"@timestamp": ts_now(), "a": "key2"}])
        assert len(rule.matches) == 2
        # This means that any one of the three n composite fields were not present
        assert rule.matches[0]["missing_field"] == ("a", "b", "c")
        assert rule.matches[1]["missing_field"] == ("d", "e.f")


@pytest.mark.usefixtures("configured", "cls_monkeypatch")
class RuleTest(unittest.TestCase):
    def test_any(self):
        event = hits(1)
        rule = AnyRule({})
        rule.add_data([event])
        assert rule.matches == [event]

    def test_maas(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['1']"

            return MockResponse()

        events = hits(1, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == events

    def test_maas_multiple_hits(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['1', '1', '1']"

            return MockResponse()

        events = hits(3, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == events

    def test_maas_multiple_hits_partial_anomaly(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['1', '0', '1']"

            return MockResponse()

        events = hits(3, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == [events[0], events[2]]

    def test_maas_gt(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['1']"

            return MockResponse()

        events = hits(1, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
                "filter_value": 0,
                "filter_condition": "greater",
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == events

    def test_maas_lt(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['-1.0']"

            return MockResponse()

        events = hits(1, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
                "filter_value": 0,
                "filter_condition": "lower",
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == events

    def test_maas_le_equals(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['-1.0']"

            return MockResponse()

        events = hits(1, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
                "filter_value": -1,
                "filter_condition": "lower_equals",
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == events

    def test_maas_le_lower(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['-2.0']"

            return MockResponse()

        events = hits(1, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
                "filter_value": -1,
                "filter_condition": "lower_equals",
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == events

    def test_maas_le_bigger(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"[1.0]"

            return MockResponse()

        events = hits(1, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
                "filter_value": -1,
                "filter_condition": "lower_equals",
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == []

    def test_maas_ge_smaller(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"[-10.0]"

            return MockResponse()

        events = hits(1, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
                "filter_value": -1,
                "filter_condition": "greater_equals",
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == []

    def test_maas_ge_equals(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['-1.0']"

            return MockResponse()

        events = hits(1, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
                "filter_value": -1,
                "filter_condition": "greater_equals",
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == events

    def test_maas_ge_greater(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['0.0']"

            return MockResponse()

        events = hits(1, x="0")
        rule_config = {
            "maas": {
                "endpoint": "http://localhost",
                "columns_mapping": [{"name": "x", "map_to": "y"}],
                "filter_value": -1,
                "filter_condition": "greater_equals",
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasRule(rule_config)
        rule.add_data(events)
        assert rule.matches == events

    def test_maas_agg_interval_buckets(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['1.0', '1.0', '1.0', '1.0']"

            return MockResponse()

        rule_config = {
            "bucket_interval": {"seconds": 10},
            "bucket_interval_timedelta": datetime.timedelta(seconds=10),
            "buffer_time": datetime.timedelta(minutes=1),
            "query_key": "foo",
            "maas": {
                "endpoint": "http://localhost",
                "filter_value": 1.0,
                "filter_condition": "equals",
            },
        }

        timestamp = datetime.datetime.now()
        payload = {
            "2014-09-26T00:00:00": {
                "bucket_aggs": {
                    "buckets": [
                        {
                            "key": "1",
                            "interval_aggs": {
                                "buckets": [
                                    {"key_as_string": timestamp, "doc_count": 2},
                                    {
                                        "key_as_string": timestamp
                                        + datetime.timedelta(seconds=10),
                                        "doc_count": 3,
                                    },
                                ]
                            },
                        },
                        {
                            "key": "2",
                            "interval_aggs": {
                                "buckets": [
                                    {"key_as_string": timestamp, "doc_count": 1},
                                    {
                                        "key_as_string": timestamp
                                        + datetime.timedelta(seconds=10),
                                        "doc_count": 4,
                                    },
                                ]
                            },
                        },
                    ]
                }
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasAggregationRule(rule_config)
        rule.add_aggregation_data(payload)
        assert rule.matches == [
            {"@timestamp": timestamp, "count": 2, "foo": "1"},
            {
                "@timestamp": timestamp + datetime.timedelta(seconds=10),
                "count": 3,
                "foo": "1",
            },
            {"@timestamp": timestamp, "count": 1, "foo": "2"},
            {
                "@timestamp": timestamp + datetime.timedelta(seconds=10),
                "count": 4,
                "foo": "2",
            },
        ]

    def test_maas_agg_interval_simple(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['1.0']"

            return MockResponse()

        rule_config = {
            "bucket_interval": {"seconds": 10},
            "bucket_interval_timedelta": datetime.timedelta(seconds=10),
            "buffer_time": datetime.timedelta(minutes=1),
            "maas": {
                "endpoint": "http://localhost",
                "filter_value": 1.0,
                "filter_condition": "equals",
            },
        }

        timestamp = datetime.datetime.now()
        interval_agg = create_bucket_aggregation(
            "interval_aggs", [{"key_as_string": timestamp, "doc_count": 10}]
        )

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasAggregationRule(rule_config)
        rule.add_aggregation_data({"2014-01-01T00:00:00Z": interval_agg})
        assert rule.matches == [{"@timestamp": timestamp, "count": 10}]

    def test_maas_agg_interval_buckets_filtered(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['1.0', '1.0', '0.0', '1.0']"

            return MockResponse()

        rule_config = {
            "bucket_interval": {"seconds": 10},
            "bucket_interval_timedelta": datetime.timedelta(seconds=10),
            "buffer_time": datetime.timedelta(minutes=1),
            "query_key": "foo",
            "maas": {
                "endpoint": "http://localhost",
                "filter_value": 1.0,
                "filter_condition": "equals",
            },
        }

        timestamp = datetime.datetime.now()
        payload = {
            "2014-09-26T00:00:00": {
                "bucket_aggs": {
                    "buckets": [
                        {
                            "key": "1",
                            "interval_aggs": {
                                "buckets": [
                                    {"key_as_string": timestamp, "doc_count": 2},
                                    {
                                        "key_as_string": timestamp
                                        + datetime.timedelta(seconds=10),
                                        "doc_count": 3,
                                    },
                                ]
                            },
                        },
                        {
                            "key": "2",
                            "interval_aggs": {
                                "buckets": [
                                    {"key_as_string": timestamp, "doc_count": 1},
                                    {
                                        "key_as_string": timestamp
                                        + datetime.timedelta(seconds=10),
                                        "doc_count": 4,
                                    },
                                ]
                            },
                        },
                    ]
                }
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasAggregationRule(rule_config)
        rule.add_aggregation_data(payload)
        assert rule.matches == [
            {"@timestamp": timestamp, "count": 2, "foo": "1"},
            {
                "@timestamp": timestamp + datetime.timedelta(seconds=10),
                "count": 3,
                "foo": "1",
            },
            {
                "@timestamp": timestamp + datetime.timedelta(seconds=10),
                "count": 4,
                "foo": "2",
            },
        ]

    def test_maas_agg_interval_buckets_metric(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['1.0', '1.0', '1.0', '1.0']"

            return MockResponse()

        rule_config = {
            "bucket_interval": {"seconds": 10},
            "bucket_interval_timedelta": datetime.timedelta(seconds=10),
            "buffer_time": datetime.timedelta(minutes=1),
            "metric_agg_key": "key",
            "metric_agg_type": "avg",
            "query_key": "foo",
            "maas": {
                "endpoint": "http://localhost",
                "filter_value": 1.0,
                "filter_condition": "equals",
            },
        }

        metric_key = "metric_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_agg_type"]
        )

        timestamp = datetime.datetime.now()
        payload = {
            "2014-09-26T00:00:00": {
                "bucket_aggs": {
                    "buckets": [
                        {
                            "key": "1",
                            "interval_aggs": {
                                "buckets": [
                                    {
                                        "key_as_string": timestamp,
                                        "doc_count": 2,
                                        metric_key: {"value": 3},
                                    },
                                    {
                                        "key_as_string": timestamp
                                        + datetime.timedelta(seconds=10),
                                        "doc_count": 3,
                                        metric_key: {"value": 2},
                                    },
                                ]
                            },
                        },
                        {
                            "key": "2",
                            "interval_aggs": {
                                "buckets": [
                                    {
                                        "key_as_string": timestamp,
                                        "doc_count": 1,
                                        metric_key: {"value": 1},
                                    },
                                    {
                                        "key_as_string": timestamp
                                        + datetime.timedelta(seconds=10),
                                        "doc_count": 4,
                                        metric_key: {"value": 5},
                                    },
                                ]
                            },
                        },
                    ]
                }
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasAggregationRule(rule_config)
        rule.add_aggregation_data(payload)
        assert rule.matches == [
            {"@timestamp": timestamp, "count": 3, "foo": "1"},
            {
                "@timestamp": timestamp + datetime.timedelta(seconds=10),
                "count": 2,
                "foo": "1",
            },
            {"@timestamp": timestamp, "count": 1, "foo": "2"},
            {
                "@timestamp": timestamp + datetime.timedelta(seconds=10),
                "count": 5,
                "foo": "2",
            },
        ]

    def test_maas_agg_buckets_filtered(self):
        def mock_post(*args, **kwargs):
            class MockResponse:
                def __init__(self):
                    self.ok = True
                    self.content = b"['1.0', '0.0']"

            return MockResponse()

        rule_config = {
            "bucket_interval": {"seconds": 10},
            "bucket_interval_timedelta": datetime.timedelta(seconds=10),
            "buffer_time": datetime.timedelta(minutes=1),
            "query_key": "foo",
            "metric_agg_key": "key",
            "metric_agg_type": "avg",
            "maas": {
                "endpoint": "http://localhost",
                "filter_value": 1.0,
                "filter_condition": "equals",
            },
        }
        metric_key = "metric_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_agg_type"]
        )

        timestamp = datetime.datetime.now()
        payload = {
            timestamp: {
                "bucket_aggs": {
                    "buckets": [
                        {"key": "bar", metric_key: {"value": 20}},
                        {"key": "baz", metric_key: {"value": 40}},
                    ]
                }
            }
        }

        self.monkeypatch.setattr(requests, "post", mock_post)

        rule = MaasAggregationRule(rule_config)
        rule.add_aggregation_data(payload)
        assert rule.matches == [{"@timestamp": timestamp, "count": 20, "foo": "bar"}]

    def test_freq(self):
        events = hits(60, timestamp_field="blah", username="qlo")
        rules = {
            "num_events": 59,
            "timeframe": datetime.timedelta(hours=1),
            "timestamp_field": "blah",
        }
        rule = FrequencyRule(rules)
        rule.add_data(events)
        assert len(rule.matches) == 1

        # Test wit query_key
        events = hits(60, timestamp_field="blah", username="qlo")
        rules["query_key"] = "username"
        rule = FrequencyRule(rules)
        rule.add_data(events)
        assert len(rule.matches) == 1

        # Doesn't match
        events = hits(60, timestamp_field="blah", username="qlo")
        rules["num_events"] = 61
        rule = FrequencyRule(rules)
        rule.add_data(events)
        assert len(rule.matches) == 0

        # garbage collection
        assert "qlo" in rule.occurrences
        rule.garbage_collect(ts_to_dt("2014-09-28T12:0:0"))
        assert rule.occurrences == {}

    def test_freq_count(self):
        rules = {
            "num_events": 100,
            "timeframe": datetime.timedelta(hours=1),
            "use_count_query": True,
        }
        # Normal match
        rule = FrequencyRule(rules)
        rule.add_count_data({ts_to_dt("2014-10-10T00:00:00"): 75})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-10-10T00:15:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-10-10T00:25:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-10-10T00:45:00"): 6})
        assert len(rule.matches) == 1

        # First data goes out of timeframe first
        rule = FrequencyRule(rules)
        rule.add_count_data({ts_to_dt("2014-10-10T00:00:00"): 75})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-10-10T00:45:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-10-10T00:55:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-10-10T01:05:00"): 6})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-10-10T01:00:00"): 75})
        assert len(rule.matches) == 1

    def test_freq_out_of_order(self):
        events = hits(60, timestamp_field="blah", username="qlo")
        rules = {
            "num_events": 59,
            "timeframe": datetime.timedelta(hours=1),
            "timestamp_field": "blah",
        }
        rule = FrequencyRule(rules)
        rule.add_data(events[:10])
        assert len(rule.matches) == 0

        # Try to add events from before the first occurrence
        rule.add_data(
            [{"blah": ts_to_dt("2014-09-26T11:00:00"), "username": "qlo"}] * 50
        )
        assert len(rule.matches) == 0

        rule.add_data(events[15:20])
        assert len(rule.matches) == 0
        rule.add_data(events[10:15])
        assert len(rule.matches) == 0
        rule.add_data(events[20:55])
        rule.add_data(events[57:])
        assert len(rule.matches) == 0
        rule.add_data(events[55:57])
        assert len(rule.matches) == 1

    def test_freq_terms(self):
        rules = {
            "num_events": 10,
            "timeframe": datetime.timedelta(hours=1),
            "query_key": "username",
        }
        rule = FrequencyRule(rules)

        terms1 = {
            ts_to_dt("2014-01-01T00:01:00Z"): [
                {"key": "userA", "doc_count": 1},
                {"key": "userB", "doc_count": 5},
            ]
        }
        terms2 = {
            ts_to_dt("2014-01-01T00:10:00Z"): [
                {"key": "userA", "doc_count": 8},
                {"key": "userB", "doc_count": 5},
            ]
        }
        terms3 = {
            ts_to_dt("2014-01-01T00:25:00Z"): [
                {"key": "userA", "doc_count": 3},
                {"key": "userB", "doc_count": 0},
            ]
        }
        # Initial data
        rule.add_terms_data(terms1)
        assert len(rule.matches) == 0

        # Match for user B
        rule.add_terms_data(terms2)
        assert len(rule.matches) == 1
        assert rule.matches[0].get("username") == "userB"

        # Match for user A
        rule.add_terms_data(terms3)
        assert len(rule.matches) == 2
        assert rule.matches[1].get("username") == "userA"

    def test_eventwindow(self):
        timeframe = datetime.timedelta(minutes=10)
        window = EventWindow(timeframe)
        timestamps = [
            ts_to_dt(x)
            for x in [
                "2014-01-01T10:00:00",
                "2014-01-01T10:05:00",
                "2014-01-01T10:03:00",
                "2014-01-01T09:55:00",
                "2014-01-01T10:09:00",
            ]
        ]
        for ts in timestamps:
            window.append([{"@timestamp": ts}, 1])

        timestamps.sort()
        for exp, actual in zip(timestamps[1:], window.data):
            assert actual[0]["@timestamp"] == exp

        window.append([{"@timestamp": ts_to_dt("2014-01-01T10:14:00")}, 1])
        timestamps.append(ts_to_dt("2014-01-01T10:14:00"))
        for exp, actual in zip(timestamps[3:], window.data):
            assert actual[0]["@timestamp"] == exp

    def test_spike_count(self):
        rules = {
            "threshold_ref": 10,
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "timestamp_field": "@timestamp",
        }
        rule = SpikeRule(rules)

        # Double rate of events at 20 seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 20})
        assert len(rule.matches) == 1

        # Downward spike
        rule = SpikeRule(rules)
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 0})
        assert len(rule.matches) == 1

    def test_spike_deep_key(self):
        rules = {
            "threshold_ref": 10,
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "timestamp_field": "@timestamp",
            "query_key": "foo.bar.baz",
        }
        rule = SpikeRule(rules)
        rule.add_data(
            [{"@timestamp": ts_to_dt("2015"), "foo": {"bar": {"baz": "LOL"}}}]
        )
        assert "LOL" in rule.windows

    def test_spike(self):
        # Events are 1 per second
        events = hits(100, timestamp_field="ts")

        # Constant rate, doesn't match
        rules = {
            "threshold_ref": 10,
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "use_count_query": False,
            "timestamp_field": "ts",
        }
        rule = SpikeRule(rules)
        rule.add_data(events)
        assert len(rule.matches) == 0

        # Double the rate of events after [50:]
        events2 = events[:50]
        for event in events[50:]:
            events2.append(event)
            events2.append({"ts": event["ts"] + datetime.timedelta(milliseconds=1)})
        rules["spike_type"] = "up"
        rule = SpikeRule(rules)
        rule.add_data(events2)
        assert len(rule.matches) == 1

        # Doesn't match
        rules["spike_height"] = 3
        rule = SpikeRule(rules)
        rule.add_data(events2)
        assert len(rule.matches) == 0

        # Downward spike
        events = events[:50] + events[75:]
        rules["spike_type"] = "down"
        rule = SpikeRule(rules)
        rule.add_data(events)
        assert len(rule.matches) == 1

        # Doesn't meet threshold_ref
        # When ref hits 11, cur is only 20
        rules["spike_height"] = 2
        rules["threshold_ref"] = 11
        rules["spike_type"] = "up"
        rule = SpikeRule(rules)
        rule.add_data(events2)
        assert len(rule.matches) == 0

        # Doesn't meet threshold_cur
        # Maximum rate of events is 20 per 10 seconds
        rules["threshold_ref"] = 10
        rules["threshold_cur"] = 30
        rule = SpikeRule(rules)
        rule.add_data(events2)
        assert len(rule.matches) == 0

        # Alert on new data
        # (At least 25 events occur before 30 seconds has elapsed)
        rules.pop("threshold_ref")
        rules["timeframe"] = datetime.timedelta(seconds=30)
        rules["threshold_cur"] = 25
        rules["spike_height"] = 2
        rules["alert_on_new_data"] = True
        rule = SpikeRule(rules)
        rule.add_data(events2)
        assert len(rule.matches) == 1

    def test_spike_query_key(self):
        events = hits(100, timestamp_field="ts", username="qlo")
        # Constant rate, doesn't match
        rules = {
            "threshold_ref": 10,
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "use_count_query": False,
            "timestamp_field": "ts",
            "query_key": "username",
        }
        rule = SpikeRule(rules)
        rule.add_data(events)
        assert len(rule.matches) == 0

        # Double the rate of events, but with a different usename
        events_bob = hits(100, timestamp_field="ts", username="bob")
        events2 = events[:50]
        for num in range(50, 99):
            events2.append(events_bob[num])
            events2.append(events[num])
        rule = SpikeRule(rules)
        rule.add_data(events2)
        assert len(rule.matches) == 0

        # Double the rate of events, with the same username
        events2 = events[:50]
        for num in range(50, 99):
            events2.append(events_bob[num])
            events2.append(events[num])
            events2.append(events[num])
        rule = SpikeRule(rules)
        rule.add_data(events2)
        assert len(rule.matches) == 1

    def test_spike_terms(self):
        rules = {
            "threshold_ref": 5,
            "spike_height": 2,
            "timeframe": datetime.timedelta(minutes=10),
            "spike_type": "both",
            "use_count_query": False,
            "timestamp_field": "ts",
            "query_key": "username",
            "use_term_query": True,
        }
        terms1 = {
            ts_to_dt("2014-01-01T00:01:00Z"): [
                {"key": "userA", "doc_count": 10},
                {"key": "userB", "doc_count": 5},
            ]
        }
        terms2 = {
            ts_to_dt("2014-01-01T00:10:00Z"): [
                {"key": "userA", "doc_count": 22},
                {"key": "userB", "doc_count": 5},
            ]
        }
        terms3 = {
            ts_to_dt("2014-01-01T00:25:00Z"): [
                {"key": "userA", "doc_count": 25},
                {"key": "userB", "doc_count": 27},
            ]
        }
        terms4 = {
            ts_to_dt("2014-01-01T00:27:00Z"): [
                {"key": "userA", "doc_count": 10},
                {"key": "userB", "doc_count": 12},
                {"key": "userC", "doc_count": 100},
            ]
        }
        terms5 = {
            ts_to_dt("2014-01-01T00:30:00Z"): [
                {"key": "userD", "doc_count": 100},
                {"key": "userC", "doc_count": 100},
            ]
        }

        rule = SpikeRule(rules)

        # Initial input
        rule.add_terms_data(terms1)
        assert len(rule.matches) == 0

        # No spike for UserA because windows not filled
        rule.add_terms_data(terms2)
        assert len(rule.matches) == 0

        # Spike for userB only
        rule.add_terms_data(terms3)
        assert len(rule.matches) == 1
        assert rule.matches[0].get("username") == "userB"

        # Test no alert for new user over threshold
        rules.pop("threshold_ref")
        rules["threshold_cur"] = 50
        rule = SpikeRule(rules)
        rule.add_terms_data(terms1)
        rule.add_terms_data(terms2)
        rule.add_terms_data(terms3)
        rule.add_terms_data(terms4)
        assert len(rule.matches) == 0

        # Test alert_on_new_data
        rules["alert_on_new_data"] = True
        rule = SpikeRule(rules)
        rule.add_terms_data(terms1)
        rule.add_terms_data(terms2)
        rule.add_terms_data(terms3)
        rule.add_terms_data(terms4)
        assert len(rule.matches) == 1

        # Test that another alert doesn't fire immediately for userC but it does
        # for userD
        rule.matches = []
        rule.add_terms_data(terms5)
        assert len(rule.matches) == 1
        assert rule.matches[0]["username"] == "userD"

    def test_spike_terms_query_key_alert_on_new_data(self):
        rules = {
            "spike_height": 1.5,
            "timeframe": datetime.timedelta(minutes=10),
            "spike_type": "both",
            "use_count_query": False,
            "timestamp_field": "ts",
            "query_key": "username",
            "use_term_query": True,
            "alert_on_new_data": True,
        }

        terms1 = {ts_to_dt("2014-01-01T00:01:00Z"): [{"key": "userA", "doc_count": 10}]}
        terms2 = {ts_to_dt("2014-01-01T00:06:00Z"): [{"key": "userA", "doc_count": 10}]}
        terms3 = {ts_to_dt("2014-01-01T00:11:00Z"): [{"key": "userA", "doc_count": 10}]}
        terms4 = {ts_to_dt("2014-01-01T00:21:00Z"): [{"key": "userA", "doc_count": 20}]}
        terms5 = {ts_to_dt("2014-01-01T00:26:00Z"): [{"key": "userA", "doc_count": 20}]}
        terms6 = {ts_to_dt("2014-01-01T00:31:00Z"): [{"key": "userA", "doc_count": 20}]}
        terms7 = {ts_to_dt("2014-01-01T00:36:00Z"): [{"key": "userA", "doc_count": 20}]}
        terms8 = {ts_to_dt("2014-01-01T00:41:00Z"): [{"key": "userA", "doc_count": 20}]}

        rule = SpikeRule(rules)

        # Initial input
        rule.add_terms_data(terms1)
        assert len(rule.matches) == 0

        # No spike for UserA because windows not filled
        rule.add_terms_data(terms2)
        assert len(rule.matches) == 0

        rule.add_terms_data(terms3)
        assert len(rule.matches) == 0

        rule.add_terms_data(terms4)
        assert len(rule.matches) == 0

        # Spike
        rule.add_terms_data(terms5)
        assert len(rule.matches) == 1

        rule.matches[:] = []

        # There will be no more spikes since all terms have the same doc_count
        rule.add_terms_data(terms6)
        assert len(rule.matches) == 0

        rule.add_terms_data(terms7)
        assert len(rule.matches) == 0

        rule.add_terms_data(terms8)
        assert len(rule.matches) == 0

    def test_spike_gap_timeframe(self):
        rules = {
            "spike_height": 2,
            "gap_timeframe": datetime.timedelta(seconds=30),
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "up",
            "timestamp_field": "@timestamp",
        }
        rule = SpikeRule(rules)

        # Double rate of events at 50 (10 + 30 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:50"): 20})
        assert len(rule.matches) == 1

    def test_spike_ref_buckets(self):
        rules = {
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "ref_window_count": 3,
            "spike_type": "both",
            "timestamp_field": "@timestamp",
        }

        rule = SpikeRule(rules)
        # Double rate of events to mean ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 20})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 40})
        assert len(rule.matches) == 1
        rule = SpikeRule(rules)
        # Half rate of events to mean ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 20})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 10})
        assert len(rule.matches) == 1

        rules["spike_ref_metric"] = "median"
        rule = SpikeRule(rules)
        # Double rate of events to mean ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 20})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 40})
        assert len(rule.matches) == 1
        rule = SpikeRule(rules)
        # Half rate of events to mean ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 20})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 10})
        assert len(rule.matches) == 1

        rules["spike_ref_metric"] = "min"
        rule = SpikeRule(rules)
        # Double rate of events to min ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 20})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 20})
        assert len(rule.matches) == 1
        rule = SpikeRule(rules)
        # Half rate of events to min ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 20})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 5})

        rules["spike_ref_metric"] = "max"
        rule = SpikeRule(rules)
        # Double rate of events to max ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 20})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 60})
        assert len(rule.matches) == 1
        rule = SpikeRule(rules)
        # Half rate of events to max ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 20})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 30})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 15})
        assert len(rule.matches) == 1

    def test_spike_ref_buckets_variable_height(self):
        rules = {
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "ref_window_count": 3,
            "spike_ref_metric": "mean",
            "spike_height_metric": "variance",
            "spike_type": "both",
            "timestamp_field": "@timestamp",
        }

        rule = SpikeRule(rules)
        # Double rate of events to mean ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 15})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 13})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 26})
        assert len(rule.matches) == 1
        rule = SpikeRule(rules)
        # Half rate of events to mean ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 15})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 13})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 0})
        assert len(rule.matches) == 1

        rules["spike_ref_metric"] = "percentile"
        rules["spike_ref_metric_args"] = {"percentile": 0.99, "params": (0, 0, 0, 1)}
        rules["spike_height_metric"] = "interquartile_range"
        rules["spike_height_metric_args"] = {"params": (0, 0, 0, 1)}
        rule = SpikeRule(rules)
        # Double rate of events to mean ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 15})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 13})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 22})
        assert len(rule.matches) == 1
        rule = SpikeRule(rules)
        # Half rate of events to mean ref at 40 (3 * 10 + 10) seconds
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:00"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:10"): 10})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:20"): 15})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:30"): 13})
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-09-26T00:00:40"): 7})
        assert len(rule.matches) == 1

    def test_blacklist(self):
        events = [
            {"@timestamp": ts_to_dt("2014-09-26T12:34:56Z"), "term": "good"},
            {"@timestamp": ts_to_dt("2014-09-26T12:34:57Z"), "term": "bad"},
            {"@timestamp": ts_to_dt("2014-09-26T12:34:58Z"), "term": "also good"},
            {"@timestamp": ts_to_dt("2014-09-26T12:34:59Z"), "term": "really bad"},
            {"@timestamp": ts_to_dt("2014-09-26T12:35:00Z"), "no_term": "bad"},
        ]
        rules = {
            "blacklist": ["bad", "really bad"],
            "compare_key": "term",
            "timestamp_field": "@timestamp",
        }
        rule = BlacklistRule(rules)
        rule.add_data(events)
        assert_matches_have(rule.matches, [("term", "bad"), ("term", "really bad")])

    def test_whitelist(self):
        events = [
            {"@timestamp": ts_to_dt("2014-09-26T12:34:56Z"), "term": "good"},
            {"@timestamp": ts_to_dt("2014-09-26T12:34:57Z"), "term": "bad"},
            {"@timestamp": ts_to_dt("2014-09-26T12:34:58Z"), "term": "also good"},
            {"@timestamp": ts_to_dt("2014-09-26T12:34:59Z"), "term": "really bad"},
            {"@timestamp": ts_to_dt("2014-09-26T12:35:00Z"), "no_term": "bad"},
        ]
        rules = {
            "whitelist": ["good", "also good"],
            "compare_key": "term",
            "ignore_null": True,
            "timestamp_field": "@timestamp",
        }
        rule = WhitelistRule(rules)
        rule.add_data(events)
        assert_matches_have(rule.matches, [("term", "bad"), ("term", "really bad")])

    def test_whitelist_dont_ignore_nulls(self):
        events = [
            {"@timestamp": ts_to_dt("2014-09-26T12:34:56Z"), "term": "good"},
            {"@timestamp": ts_to_dt("2014-09-26T12:34:57Z"), "term": "bad"},
            {"@timestamp": ts_to_dt("2014-09-26T12:34:58Z"), "term": "also good"},
            {"@timestamp": ts_to_dt("2014-09-26T12:34:59Z"), "term": "really bad"},
            {"@timestamp": ts_to_dt("2014-09-26T12:35:00Z"), "no_term": "bad"},
        ]
        rules = {
            "whitelist": ["good", "also good"],
            "compare_key": "term",
            "ignore_null": True,
            "timestamp_field": "@timestamp",
        }
        rules["ignore_null"] = False
        rule = WhitelistRule(rules)
        rule.add_data(events)
        assert_matches_have(
            rule.matches, [("term", "bad"), ("term", "really bad"), ("no_term", "bad")]
        )

    def test_change(self):
        events = hits(10, username="qlo", term="good", second_term="yes")
        events[8].pop("term")
        events[8].pop("second_term")
        events[9]["term"] = "bad"
        events[9]["second_term"] = "no"
        rules = {
            "compound_compare_key": ["term", "second_term"],
            "query_key": "username",
            "ignore_null": True,
            "timestamp_field": "@timestamp",
        }
        rule = ChangeRule(rules)
        rule.add_data(events)
        assert_matches_have(rule.matches, [("term", "bad", "second_term", "no")])

        # Unhashable QK
        events2 = hits(10, username=["qlo"], term="good", second_term="yes")
        events2[9]["term"] = "bad"
        events2[9]["second_term"] = "no"
        rule = ChangeRule(rules)
        rule.add_data(events2)
        assert_matches_have(rule.matches, [("term", "bad", "second_term", "no")])

        # Don't ignore nulls
        rules["ignore_null"] = False
        rule = ChangeRule(rules)
        rule.add_data(events)
        assert_matches_have(
            rule.matches, [("username", "qlo"), ("term", "bad", "second_term", "no")]
        )

        # With timeframe
        rules["timeframe"] = datetime.timedelta(seconds=2)
        rules["ignore_null"] = True
        rule = ChangeRule(rules)
        rule.add_data(events)
        assert_matches_have(rule.matches, [("term", "bad", "second_term", "no")])

        # With timeframe, doesn't match
        events = events[:8] + events[9:]
        rules["timeframe"] = datetime.timedelta(seconds=1)
        rule = ChangeRule(rules)
        rule.add_data(events)
        assert rule.matches == []

    def test_flatline(self):
        events = hits(40)
        rules = {
            "timeframe": datetime.timedelta(seconds=30),
            "threshold": 2,
            "timestamp_field": "@timestamp",
        }

        rule = FlatlineRule(rules)

        # 1 hit should cause an alert until after at least 30 seconds pass
        rule.add_data(hits(1))
        assert rule.matches == []

        # Add hits with timestamps 2014-09-26T12:00:00 --> 2014-09-26T12:00:09
        rule.add_data(events[0:10])

        # This will be run at the end of the hits
        rule.garbage_collect(ts_to_dt("2014-09-26T12:00:11Z"))
        assert rule.matches == []

        # This would be run if the query returned nothing for a future timestamp
        rule.garbage_collect(ts_to_dt("2014-09-26T12:00:45Z"))
        assert len(rule.matches) == 1

        # After another garbage collection, since there are still no events, a new
        # match is added
        rule.garbage_collect(ts_to_dt("2014-09-26T12:00:50Z"))
        assert len(rule.matches) == 2

        # Add hits with timestamps 2014-09-26T12:00:30 --> 2014-09-26T12:00:39
        rule.add_data(events[30:])

        # Now that there is data in the last 30 minutes, no more matches should be added
        rule.garbage_collect(ts_to_dt("2014-09-26T12:00:55Z"))
        assert len(rule.matches) == 2

        # After that window passes with no more data, a new match is added
        rule.garbage_collect(ts_to_dt("2014-09-26T12:01:11Z"))
        assert len(rule.matches) == 3

    def test_flatline_no_data(self):
        rules = {
            "timeframe": datetime.timedelta(seconds=30),
            "threshold": 2,
            "timestamp_field": "@timestamp",
        }

        rule = FlatlineRule(rules)

        # Initial lack of data
        rule.garbage_collect(ts_to_dt("2014-09-26T12:00:00Z"))
        assert len(rule.matches) == 0

        # Passed the timeframe, still no events
        rule.garbage_collect(ts_to_dt("2014-09-26T12:35:00Z"))
        assert len(rule.matches) == 1

    def test_flatline_count(self):
        rules = {
            "timeframe": datetime.timedelta(seconds=30),
            "threshold": 1,
            "timestamp_field": "@timestamp",
        }
        rule = FlatlineRule(rules)
        rule.add_count_data({ts_to_dt("2014-10-11T00:00:00"): 1})
        rule.garbage_collect(ts_to_dt("2014-10-11T00:00:10"))
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-10-11T00:00:15"): 0})
        rule.garbage_collect(ts_to_dt("2014-10-11T00:00:20"))
        assert len(rule.matches) == 0
        rule.add_count_data({ts_to_dt("2014-10-11T00:00:35"): 0})
        assert len(rule.matches) == 1

    def test_flatline_query_key(self):
        rules = {
            "timeframe": datetime.timedelta(seconds=30),
            "threshold": 1,
            "use_query_key": True,
            "query_key": "qk",
            "timestamp_field": "@timestamp",
        }

        rule = FlatlineRule(rules)

        # Adding two separate query keys, the flatline rule should trigger for both
        rule.add_data(hits(1, qk="key1"))
        rule.add_data(hits(1, qk="key2"))
        rule.add_data(hits(1, qk="key3"))
        assert rule.matches == []

        # This will be run at the end of the hits
        rule.garbage_collect(ts_to_dt("2014-09-26T12:00:11Z"))
        assert rule.matches == []

        # Add new data from key3. It will not immediately cause an alert
        rule.add_data([create_event(ts_to_dt("2014-09-26T12:00:20Z"), qk="key3")])

        # key1 and key2 have not had any new data, so they will trigger the
        # flatline alert
        timestamp = "2014-09-26T12:00:45Z"
        rule.garbage_collect(ts_to_dt(timestamp))
        assert len(rule.matches) == 2
        assert set(["key1", "key2"]) == set(
            [m["key"] for m in rule.matches if m["@timestamp"] == timestamp]
        )

        # Next time the rule runs, all 3 keys still have no data, so all three
        # will cause an alert
        timestamp = "2014-09-26T12:01:20Z"
        rule.garbage_collect(ts_to_dt(timestamp))
        assert len(rule.matches) == 5
        assert set(["key1", "key2", "key3"]) == set(
            [m["key"] for m in rule.matches if m["@timestamp"] == timestamp]
        )

    def test_flatline_forget_query_key(self):
        rules = {
            "timeframe": datetime.timedelta(seconds=30),
            "threshold": 1,
            "query_key": "qk",
            "forget_keys": True,
            "timestamp_field": "@timestamp",
        }

        rule = FlatlineRule(rules)

        # Adding two separate query keys, the flatline rule should trigger for both
        rule.add_data(hits(1, qk="key1"))
        assert rule.matches == []

        # This will be run at the end of the hits
        rule.garbage_collect(ts_to_dt("2014-09-26T12:00:11Z"))
        assert rule.matches == []

        # Key1 should not alert
        timestamp = "2014-09-26T12:00:45Z"
        rule.garbage_collect(ts_to_dt(timestamp))
        assert len(rule.matches) == 1
        rule.matches = []

        # key1 was forgotten, so no more matches
        rule.garbage_collect(ts_to_dt("2014-09-26T12:01:11Z"))
        assert rule.matches == []

    def test_cardinality_max(self):
        rules = {
            "max_cardinality": 4,
            "timeframe": datetime.timedelta(minutes=10),
            "cardinality_field": "user",
            "timestamp_field": "@timestamp",
        }
        rule = CardinalityRule(rules)

        # Add 4 different usernames
        users = ["bill", "coach", "zoey", "louis"]
        for user in users:
            event = {"@timestamp": datetime.datetime.now(), "user": user}
            rule.add_data([event])
            assert len(rule.matches) == 0
        rule.garbage_collect(datetime.datetime.now())

        # Add a duplicate, stay at 4 cardinality
        event = {"@timestamp": datetime.datetime.now(), "user": "coach"}
        rule.add_data([event])
        rule.garbage_collect(datetime.datetime.now())
        assert len(rule.matches) == 0

        # Next unique will trigger
        event = {"@timestamp": datetime.datetime.now(), "user": "francis"}
        rule.add_data([event])
        rule.garbage_collect(datetime.datetime.now())
        assert len(rule.matches) == 1
        rule.matches = []

        # 15 minutes later, adding more will not trigger an alert
        users = ["nick", "rochelle", "ellis"]
        for user in users:
            event = {
                "@timestamp": datetime.datetime.now() + datetime.timedelta(minutes=15),
                "user": user,
            }
            rule.add_data([event])
            assert len(rule.matches) == 0

    def test_cardinality_min(self):
        rules = {
            "min_cardinality": 4,
            "timeframe": datetime.timedelta(minutes=10),
            "cardinality_field": "user",
            "timestamp_field": "@timestamp",
        }
        rule = CardinalityRule(rules)

        # Add 2 different usernames, no alert because time hasn't elapsed
        users = ["foo", "bar"]
        for user in users:
            event = {"@timestamp": datetime.datetime.now(), "user": user}
            rule.add_data([event])
            assert len(rule.matches) == 0
        rule.garbage_collect(datetime.datetime.now())

        # Add 3 more unique ad t+5 mins
        users = ["faz", "fuz", "fiz"]
        for user in users:
            event = {
                "@timestamp": datetime.datetime.now() + datetime.timedelta(minutes=5),
                "user": user,
            }
            rule.add_data([event])
        rule.garbage_collect(datetime.datetime.now() + datetime.timedelta(minutes=5))
        assert len(rule.matches) == 0

        # Adding the same one again at T+15 causes an alert
        user = "faz"
        event = {
            "@timestamp": datetime.datetime.now() + datetime.timedelta(minutes=15),
            "user": user,
        }
        rule.add_data([event])
        rule.garbage_collect(datetime.datetime.now() + datetime.timedelta(minutes=15))
        assert len(rule.matches) == 1

    def test_cardinality_qk(self):
        rules = {
            "max_cardinality": 2,
            "timeframe": datetime.timedelta(minutes=10),
            "cardinality_field": "foo",
            "timestamp_field": "@timestamp",
            "query_key": "user",
        }
        rule = CardinalityRule(rules)

        # Add 3 different usernames, one value each
        users = ["foo", "bar", "baz"]
        for user in users:
            event = {
                "@timestamp": datetime.datetime.now(),
                "user": user,
                "foo": "foo" + user,
            }
            rule.add_data([event])
            assert len(rule.matches) == 0
        rule.garbage_collect(datetime.datetime.now())

        # Add 2 more unique for "baz", one alert per value
        values = ["faz", "fuz", "fiz"]
        for value in values:
            event = {
                "@timestamp": datetime.datetime.now() + datetime.timedelta(minutes=5),
                "user": "baz",
                "foo": value,
            }
            rule.add_data([event])
        rule.garbage_collect(datetime.datetime.now() + datetime.timedelta(minutes=5))
        assert len(rule.matches) == 2
        assert rule.matches[0]["user"] == "baz"
        assert rule.matches[1]["user"] == "baz"
        assert rule.matches[0]["foo"] == "fuz"
        assert rule.matches[1]["foo"] == "fiz"

    def test_cardinality_nested_cardinality_field(self):
        rules = {
            "max_cardinality": 4,
            "timeframe": datetime.timedelta(minutes=10),
            "cardinality_field": "d.ip",
            "timestamp_field": "@timestamp",
        }
        rule = CardinalityRule(rules)

        # Add 4 different IPs
        ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        for ip in ips:
            event = {"@timestamp": datetime.datetime.now(), "d": {"ip": ip}}
            rule.add_data([event])
            assert len(rule.matches) == 0
        rule.garbage_collect(datetime.datetime.now())

        # Add a duplicate, stay at 4 cardinality
        event = {"@timestamp": datetime.datetime.now(), "d": {"ip": "10.0.0.4"}}
        rule.add_data([event])
        rule.garbage_collect(datetime.datetime.now())
        assert len(rule.matches) == 0

        # Add an event with no IP, stay at 4 cardinality
        event = {"@timestamp": datetime.datetime.now()}
        rule.add_data([event])
        rule.garbage_collect(datetime.datetime.now())
        assert len(rule.matches) == 0

        # Next unique will trigger
        event = {"@timestamp": datetime.datetime.now(), "d": {"ip": "10.0.0.5"}}
        rule.add_data([event])
        rule.garbage_collect(datetime.datetime.now())
        assert len(rule.matches) == 1
        rule.matches = []

        # 15 minutes later, adding more will not trigger an alert
        ips = ["10.0.0.6", "10.0.0.7", "10.0.0.8"]
        for ip in ips:
            event = {
                "@timestamp": datetime.datetime.now() + datetime.timedelta(minutes=15),
                "d": {"ip": ip},
            }
            rule.add_data([event])
            assert len(rule.matches) == 0

    def test_base_aggregation_constructor(self):
        rules = {
            "bucket_interval_timedelta": datetime.timedelta(seconds=10),
            "buffer_time": datetime.timedelta(minutes=1),
            "timestamp_field": "@timestamp",
        }

        # Test time period constructor logic
        rules["bucket_interval"] = {"seconds": 10}
        rule = TestBaseAggregationRule(rules)
        assert rule.rules["bucket_interval_period"] == "10s"

        rules["bucket_interval"] = {"minutes": 5}
        rule = TestBaseAggregationRule(rules)
        assert rule.rules["bucket_interval_period"] == "5m"

        rules["bucket_interval"] = {"hours": 4}
        rule = TestBaseAggregationRule(rules)
        assert rule.rules["bucket_interval_period"] == "4h"

        rules["bucket_interval"] = {"days": 2}
        rule = TestBaseAggregationRule(rules)
        assert rule.rules["bucket_interval_period"] == "2d"

        rules["bucket_interval"] = {"weeks": 1}
        rule = TestBaseAggregationRule(rules)
        assert rule.rules["bucket_interval_period"] == "1w"

        # buffer_time evenly divisible by bucket_interval
        with pytest.raises(EAException):
            rules["bucket_interval_timedelta"] = datetime.timedelta(seconds=13)
            rule = TestBaseAggregationRule(rules)

        # run_every evenly divisible by bucket_interval
        rules["use_run_every_query_size"] = True
        rules["run_every"] = datetime.timedelta(minutes=2)
        rules["bucket_interval_timedelta"] = datetime.timedelta(seconds=10)
        rule = TestBaseAggregationRule(rules)

        with pytest.raises(EAException):
            rules["bucket_interval_timedelta"] = datetime.timedelta(seconds=13)
            rule = TestBaseAggregationRule(rules)

    def test_base_aggregation_payloads(self):
        with mock.patch.object(
            TestBaseAggregationRule, "check_matches", return_value=None
        ) as mock_check_matches:
            rules = {
                "bucket_interval": {"seconds": 10},
                "bucket_interval_timedelta": datetime.timedelta(seconds=10),
                "buffer_time": datetime.timedelta(minutes=5),
                "timestamp_field": "@timestamp",
            }

            timestamp = datetime.datetime.now()
            interval_agg = create_bucket_aggregation(
                "interval_aggs", [{"key_as_string": "2014-01-01T00:00:00Z"}]
            )
            rule = TestBaseAggregationRule(rules)

            # Payload not wrapped
            rule.add_aggregation_data({timestamp: {}})
            mock_check_matches.assert_called_once_with(timestamp, None, {})
            mock_check_matches.reset_mock()

            # Payload wrapped by date_histogram
            interval_agg_data = {timestamp: interval_agg}
            rule.add_aggregation_data(interval_agg_data)
            mock_check_matches.assert_called_once_with(
                ts_to_dt("2014-01-01T00:00:00Z"),
                None,
                {"key_as_string": "2014-01-01T00:00:00Z"},
            )
            mock_check_matches.reset_mock()

            # Payload wrapped by terms
            bucket_agg_data = {
                timestamp: create_bucket_aggregation("bucket_aggs", [{"key": "qk"}])
            }
            rule.add_aggregation_data(bucket_agg_data)
            mock_check_matches.assert_called_once_with(timestamp, "qk", {"key": "qk"})
            mock_check_matches.reset_mock()

            # Payload wrapped by terms and date_histogram
            bucket_interval_agg_data = {
                timestamp: create_bucket_aggregation(
                    "bucket_aggs",
                    [{"key": "qk", "interval_aggs": interval_agg["interval_aggs"]}],
                )
            }
            rule.add_aggregation_data(bucket_interval_agg_data)
            mock_check_matches.assert_called_once_with(
                ts_to_dt("2014-01-01T00:00:00Z"),
                "qk",
                {"key_as_string": "2014-01-01T00:00:00Z"},
            )
            mock_check_matches.reset_mock()

    def test_metric_aggregation(self):
        rules = {
            "buffer_time": datetime.timedelta(minutes=5),
            "timestamp_field": "@timestamp",
            "metric_agg_type": "avg",
            "metric_agg_key": "cpu_pct",
        }

        # Check threshold logic
        with pytest.raises(EAException):
            rule = MetricAggregationRule(rules)

        rules["min_threshold"] = 0.1
        rules["max_threshold"] = 0.8

        rule = MetricAggregationRule(rules)

        assert rule.rules["aggregation_query_element"] == {
            "metric_cpu_pct_avg": {"avg": {"field": "cpu_pct"}}
        }

        assert rule.crossed_thresholds(None) is False
        assert rule.crossed_thresholds(0.09) is True
        assert rule.crossed_thresholds(0.10) is False
        assert rule.crossed_thresholds(0.79) is False
        assert rule.crossed_thresholds(0.81) is True

        rule.check_matches(
            datetime.datetime.now(), None, {"metric_cpu_pct_avg": {"value": None}}
        )
        rule.check_matches(
            datetime.datetime.now(), None, {"metric_cpu_pct_avg": {"value": 0.5}}
        )
        assert len(rule.matches) == 0

        rule.check_matches(
            datetime.datetime.now(), None, {"metric_cpu_pct_avg": {"value": 0.05}}
        )
        rule.check_matches(
            datetime.datetime.now(), None, {"metric_cpu_pct_avg": {"value": 0.95}}
        )
        assert len(rule.matches) == 2

        rules["query_key"] = "qk"
        rule = MetricAggregationRule(rules)
        rule.check_matches(
            datetime.datetime.now(), "qk_val", {"metric_cpu_pct_avg": {"value": 0.95}}
        )
        assert rule.matches[0]["qk"] == "qk_val"

    def test_spike_metric_agg(self):
        rule_config = {
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "metric_agg_key": "key",
            "metric_agg_type": "avg",
        }
        metric_key = "metric_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_agg_type"]
        )

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {"2014-09-26T00:00:00": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        assert rule.garbage_collect_count == 1
        payload = {"2014-09-26T00:00:10": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert rule.garbage_collect_count == 0
        assert len(rule.matches) == 0

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {"2014-09-26T00:00:00": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        assert rule.garbage_collect_count == 1
        assert len(rule.matches) == 0
        payload = {"2014-09-26T00:00:10": {metric_key: {"value": 20}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert rule.garbage_collect_count == 0
        assert len(rule.matches) == 1

    def test_spike_metric_agg_query_key(self):
        rule_config = {
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "metric_agg_key": "key",
            "metric_agg_type": "avg",
            "query_key": "foo",
        }
        metric_key = "metric_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_agg_type"]
        )

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {
            "2014-09-26T00:00:00": {
                "bucket_aggs": {
                    "buckets": [
                        {"key": "bar", metric_key: {"value": 10}},
                        {"key": "baz", metric_key: {"value": 20}},
                    ]
                }
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        payload = {
            "2014-09-26T00:00:10": {
                "bucket_aggs": {
                    "buckets": [
                        {"key": "bar", metric_key: {"value": 10}},
                        {"key": "baz", metric_key: {"value": 20}},
                    ]
                }
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 0

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {
            "2014-09-26T00:00:00": {
                "bucket_aggs": {
                    "buckets": [
                        {"key": "bar", metric_key: {"value": 10}},
                        {"key": "baz", metric_key: {"value": 20}},
                    ]
                }
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        payload = {
            "2014-09-26T00:00:10": {
                "bucket_aggs": {
                    "buckets": [
                        {"key": "bar", metric_key: {"value": 20}},
                        {"key": "baz", metric_key: {"value": 20}},
                    ]
                }
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 1

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {
            "2014-09-26T00:00:00": {
                "bucket_aggs": {
                    "buckets": [
                        {"key": "bar", metric_key: {"value": 10}},
                        {"key": "baz", metric_key: {"value": 20}},
                    ]
                }
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        payload = {
            "2014-09-26T00:00:10": {
                "bucket_aggs": {
                    "buckets": [
                        {"key": "bar", metric_key: {"value": 20}},
                        {"key": "baz", metric_key: {"value": 40}},
                    ]
                }
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 2

    def test_spike_metric_agg_multiple_query_keys(self):
        rule_config = {
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "metric_agg_key": "key",
            "metric_agg_type": "avg",
            "query_key": ["foo", "foo2"],
        }
        metric_key = "metric_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_agg_type"]
        )

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {
            "2014-09-26T00:00:00": {
                "bucket_aggs": {
                    "buckets": [
                        {
                            "key": "bar",
                            "bucket_aggs": {
                                "buckets": [
                                    {"key": "bar2", metric_key: {"value": 10}},
                                    {"key": "baz2", metric_key: {"value": 15}},
                                ]
                            },
                        },
                        {
                            "key": "baz",
                            "bucket_aggs": {
                                "buckets": [
                                    {"key": "bar2", metric_key: {"value": 20}},
                                    {"key": "baz2", metric_key: {"value": 20}},
                                ]
                            },
                        },
                    ]
                }
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        payload = {
            "2014-09-26T00:00:10": {
                "bucket_aggs": {
                    "buckets": [
                        {
                            "key": "bar",
                            "bucket_aggs": {
                                "buckets": [
                                    {"key": "bar2", metric_key: {"value": 12}},
                                    {"key": "baz2", metric_key: {"value": 15}},
                                ]
                            },
                        },
                        {
                            "key": "baz",
                            "bucket_aggs": {
                                "buckets": [
                                    {"key": "bar2", metric_key: {"value": 30}},
                                    {"key": "baz2", metric_key: {"value": 20}},
                                ]
                            },
                        },
                    ]
                }
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 0

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {
            "2014-09-26T00:00:00": {
                "bucket_aggs": {
                    "buckets": [
                        {
                            "key": "bar",
                            "bucket_aggs": {
                                "buckets": [
                                    {"key": "bar2", metric_key: {"value": 10}},
                                    {"key": "baz2", metric_key: {"value": 15}},
                                ]
                            },
                        },
                        {
                            "key": "baz",
                            "bucket_aggs": {
                                "buckets": [
                                    {"key": "bar2", metric_key: {"value": 20}},
                                    {"key": "baz2", metric_key: {"value": 20}},
                                ]
                            },
                        },
                    ]
                }
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        payload = {
            "2014-09-26T00:00:10": {
                "bucket_aggs": {
                    "buckets": [
                        {
                            "key": "bar",
                            "bucket_aggs": {
                                "buckets": [
                                    {"key": "bar2", metric_key: {"value": 25}},
                                    {"key": "baz2", metric_key: {"value": 15}},
                                ]
                            },
                        },
                        {
                            "key": "baz",
                            "bucket_aggs": {
                                "buckets": [
                                    {"key": "bar2", metric_key: {"value": 40}},
                                    {"key": "baz2", metric_key: {"value": 50}},
                                ]
                            },
                        },
                    ]
                }
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 3

    def test_spike_metric_agg_variable_height_basic(self):
        rule_config = {
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "metric_agg_key": "key",
            "metric_agg_type": "avg",
            "metric_ref_agg_type": "median_absolute_deviation",
        }
        metric_key = "metric_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_agg_type"]
        )
        metric_ref_key = "metric_ref_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_ref_agg_type"]
        )

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {
            "2014-09-26T00:00:00": {
                metric_key: {"value": 10},
                metric_ref_key: {"value": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        payload = {
            "2014-09-26T00:00:10": {
                metric_key: {"value": 10},
                metric_ref_key: {"value": 5},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 0

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {
            "2014-09-26T00:00:00": {
                metric_key: {"value": 10},
                metric_ref_key: {"value": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        payload = {
            "2014-09-26T00:00:10": {
                metric_key: {"value": 16},
                metric_ref_key: {"value": 5},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 1

    def test_spike_metric_agg_variable_height_extended(self):
        rule_config = {
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "metric_agg_key": "key",
            "metric_agg_type": "avg",
            "metric_ref_agg_type": "std_deviation",
        }
        metric_key = "metric_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_agg_type"]
        )
        metric_ref_key = "metric_ref_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_ref_agg_type"]
        )

        rule = SpikeMetricAggregationRule(copy.deepcopy(rule_config))
        payload = {
            "2014-09-26T00:00:00": {
                metric_key: {"value": 10},
                metric_ref_key: {"std_deviation": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        payload = {
            "2014-09-26T00:00:10": {
                metric_key: {"value": 10},
                metric_ref_key: {"std_deviation": 5},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 0

        rule = SpikeMetricAggregationRule(copy.deepcopy(rule_config))
        payload = {
            "2014-09-26T00:00:00": {
                metric_key: {"value": 10},
                metric_ref_key: {"std_deviation": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        payload = {
            "2014-09-26T00:00:10": {
                metric_key: {"value": 16},
                metric_ref_key: {"std_deviation": 5},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 1

    def test_spike_metric_agg_ref_buckets(self):
        rule_config = {
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "metric_agg_key": "key",
            "metric_agg_type": "avg",
            "ref_window_count": 3,
            "spike_ref_metric": "mean",
        }
        metric_key = "metric_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_agg_type"]
        )

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {"2014-09-26T00:00:00": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        assert rule.garbage_collect_count == 1
        payload = {"2014-09-26T00:00:10": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert rule.garbage_collect_count == 2
        payload = {"2014-09-26T00:00:20": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:20"))
        assert rule.garbage_collect_count == 3
        payload = {"2014-09-26T00:00:30": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:30"))
        assert rule.garbage_collect_count == 0
        assert len(rule.matches) == 0

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {"2014-09-26T00:00:00": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        assert rule.garbage_collect_count == 1
        assert len(rule.matches) == 0
        payload = {"2014-09-26T00:00:10": {metric_key: {"value": 14}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert rule.garbage_collect_count == 2
        assert len(rule.matches) == 0
        payload = {"2014-09-26T00:00:20": {metric_key: {"value": 11}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:20"))
        assert rule.garbage_collect_count == 3
        assert len(rule.matches) == 0
        payload = {"2014-09-26T00:00:30": {metric_key: {"value": 24}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:30"))
        assert rule.garbage_collect_count == 0
        assert len(rule.matches) == 1

    def test_spike_metric_agg_ref_buckets_variable_height(self):
        rule_config = {
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "metric_agg_key": "key",
            "metric_agg_type": "avg",
            "ref_window_count": 3,
            "spike_ref_metric": "mean",
            "spike_height_metric": "stdev",
        }
        metric_key = "metric_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_agg_type"]
        )

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {"2014-09-26T00:00:00": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        assert len(rule.matches) == 0
        payload = {"2014-09-26T00:00:10": {metric_key: {"value": 11}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 0
        payload = {"2014-09-26T00:00:20": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:20"))
        assert len(rule.matches) == 0
        payload = {"2014-09-26T00:00:30": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:30"))
        assert len(rule.matches) == 0

        rule = SpikeMetricAggregationRule(rule_config)
        payload = {"2014-09-26T00:00:00": {metric_key: {"value": 10}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        assert len(rule.matches) == 0
        payload = {"2014-09-26T00:00:10": {metric_key: {"value": 14}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 0
        payload = {"2014-09-26T00:00:20": {metric_key: {"value": 11}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:20"))
        assert len(rule.matches) == 0
        payload = {"2014-09-26T00:00:30": {metric_key: {"value": 16}}}
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:30"))
        assert len(rule.matches) == 1

    def test_spike_metric_agg_ref_buckets_agg_variable_height(self):
        rule_config = {
            "spike_height": 2,
            "timeframe": datetime.timedelta(seconds=10),
            "spike_type": "both",
            "metric_agg_key": "key",
            "metric_agg_type": "avg",
            "metric_ref_agg_type": "std_deviation",
            "spike_ref_metric": "mean",
            "spike_height_metric": "max",
            "ref_window_count": 3,
        }
        metric_key = "metric_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_agg_type"]
        )
        metric_ref_key = "metric_ref_{}_{}".format(
            rule_config["metric_agg_key"], rule_config["metric_ref_agg_type"]
        )

        rule = SpikeMetricAggregationRule(copy.deepcopy(rule_config))
        payload = {
            "2014-09-26T00:00:00": {
                metric_key: {"value": 10},
                metric_ref_key: {"std_deviation": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        assert len(rule.matches) == 0
        payload = {
            "2014-09-26T00:00:10": {
                metric_key: {"value": 10},
                metric_ref_key: {"std_deviation": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 0
        payload = {
            "2014-09-26T00:00:20": {
                metric_key: {"value": 10},
                metric_ref_key: {"std_deviation": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:20"))
        assert len(rule.matches) == 0
        payload = {
            "2014-09-26T00:00:30": {
                metric_key: {"value": 10},
                metric_ref_key: {"std_deviation": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:30"))
        assert len(rule.matches) == 0

        rule = SpikeMetricAggregationRule(copy.deepcopy(rule_config))
        payload = {
            "2014-09-26T00:00:00": {
                metric_key: {"value": 10},
                metric_ref_key: {"std_deviation": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect("2014-09-26T00:00:00")
        assert len(rule.matches) == 0
        payload = {
            "2014-09-26T00:00:10": {
                metric_key: {"value": 12},
                metric_ref_key: {"std_deviation": 4},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:10"))
        assert len(rule.matches) == 0
        payload = {
            "2014-09-26T00:00:20": {
                metric_key: {"value": 11},
                metric_ref_key: {"std_deviation": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:20"))
        assert len(rule.matches) == 0
        payload = {
            "2014-09-26T00:00:30": {
                metric_key: {"value": 19},
                metric_ref_key: {"std_deviation": 3},
            }
        }
        rule.add_aggregation_data(payload)
        rule.garbage_collect(ts_to_dt("2014-09-26T00:00:30"))
        assert len(rule.matches) == 1

    def test_correlation_rule(self):
        rules = {
            "event_name_field": "rule_name",
            "state_machine": {
                "events": [
                    {"name": "a", "src": "ST", "dst": "A"},  # initial_event
                    {"name": "b", "src": "A", "dst": "B"},
                    {"name": "c", "src": "B", "dst": "C"},
                    {"name": "d", "src": "B", "dst": "D"},
                ],
                "final_states": ["C", "D"],
            },
            "include": [],
        }

        # no initial event
        rule = CorrelationRule(rules)
        rule.add_data(
            [
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"},
            ]
        )
        assert len(rule.state_machines["all"]) == 0

        rule = CorrelationRule(rules)
        # initial event
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        assert rule.state_machines["all"][0].log[1][0] == "a"
        assert rule.state_machines["all"][0].log[1][1] == "ST"
        assert rule.state_machines["all"][0].log[1][2] == "A"
        rule.add_data(
            [
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"},
            ]
        )
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 1

        rule = CorrelationRule(rules)
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 2
        assert len(rule.matches) == 0
        rule.add_data(
            [
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"},
            ]
        )
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 2
        rule.add_data(
            [
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"},
            ]
        )
        assert len(rule.state_machines["all"]) == 0
        assert len(rule.matches) == 2

        rule = CorrelationRule(rules)
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        assert rule.state_machines["all"][0].current == "B"
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        assert rule.state_machines["all"][0].current == "B"
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 2
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 3
        assert len(rule.matches) == 0
        rule.add_data(
            [
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"},
            ]
        )
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 3

        rule = CorrelationRule(rules)
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 2
        assert len(rule.matches) == 0
        rule.add_data(
            [
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"},
            ]
        )
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 2

    def test_correlation_rule_no_multiple_alerts(self):
        rules = {
            "event_name_field": "rule_name",
            "state_machine": {
                "events": [
                    {"name": "a", "src": "ST", "dst": "A"},  # initial_event
                    {"name": "b", "src": "A", "dst": "B"},
                    {"name": "c", "src": "B", "dst": "C"},
                    {"name": "d", "src": "B", "dst": "D"},
                ],
                "final_states": ["C", "D"],
            },
            "include": [],
            "multiple_alerts": False,
        }
        rule = CorrelationRule(rules)
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 2
        assert len(rule.matches) == 0
        rule.add_data(
            [
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"},
            ]
        )
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 1

        rule = CorrelationRule(rules)
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 2
        assert len(rule.matches) == 0
        rule.add_data(
            [
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"},
            ]
        )
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 2

    def test_correlation_rule_no_remove_on_final(self):
        rules = {
            "event_name_field": "rule_name",
            "state_machine": {
                "events": [
                    {"name": "a", "src": "ST", "dst": "A"},  # initial_event
                    {"name": "b", "src": "A", "dst": "B"},
                    {"name": "c", "src": "B", "dst": "C"},
                    {"name": "d", "src": "B", "dst": "D"},
                    {"name": "x", "src": "D", "dst": "B"},
                ],
                "final_states": ["C", "D"],
            },
            "include": [],
        }
        rule = CorrelationRule(rules)
        rule.add_data(
            [
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"},
            ]
        )
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "d"}])
        # state D is a final state but has outgoing events
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 1
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "x"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 1
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "d"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 2

        rule = CorrelationRule(rules)
        rule.add_data(
            [
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"},
                {"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "b"},
            ]
        )
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "c"}])
        # state C has no outgoing events -> will be removed
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 1

    def test_correlation_rule_conditions(self):
        rules = {
            "event_name_field": "rule_name",
            "state_machine": {
                "events": [
                    {"name": "a", "src": "ST", "dst": "A"},
                    {"name": "b", "src": "A", "dst": "B"},
                    {"name": "c", "src": "B", "dst": "C"},
                    {"name": "d", "src": "C", "dst": "D"},
                ],
                "final_states": ["D"],
                "conditions": [
                    {
                        "name": "single",
                        "src": "B",
                        "dst": "C",
                        "timeframe": {"seconds": 10},
                    },
                    {
                        "name": "multiple",
                        "src": "B",
                        "dst": "D",
                        "timeframe": {"seconds": 15},
                    },
                ],
            },
            "include": [],
        }

        rule = CorrelationRule(rules)
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:38Z", "rule_name": "b"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:40Z", "rule_name": "c"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:42Z", "rule_name": "d"}])
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 1

        rule = CorrelationRule(rules)
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:38Z", "rule_name": "b"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:50Z", "rule_name": "c"}])
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 0

        rule = CorrelationRule(rules)
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:38Z", "rule_name": "b"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:45Z", "rule_name": "c"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:55Z", "rule_name": "d"}])
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 0

    def test_correlation_rule_conditions2(self):
        rules = {
            "event_name_field": "rule_name",
            "state_machine": {
                "events": [
                    {"name": "a", "src": ["ST", "C"], "dst": "A"},
                    {"name": "b", "src": "A", "dst": "B"},
                    {"name": "c", "src": "A", "dst": "C"},
                ],
                "final_states": ["B"],
                "conditions": [
                    {
                        "name": "single",
                        "src": "A",
                        "dst": "B",
                        "timeframe": {"seconds": 10},
                    },
                ],
            },
            "multiple_alerts": False,
            "include": [],
        }

        rule = CorrelationRule(rules)
        rule.add_data([{"@timestamp": "2020-03-26T12:23:34Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:23:50Z", "rule_name": "c"}])
        assert len(rule.state_machines["all"]) == 1
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:24:00Z", "rule_name": "a"}])
        assert len(rule.state_machines["all"]) == 2
        assert len(rule.matches) == 0
        rule.add_data([{"@timestamp": "2020-03-26T12:24:05Z", "rule_name": "b"}])
        assert len(rule.state_machines) == 0
        assert len(rule.matches) == 1
