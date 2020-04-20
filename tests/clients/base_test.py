import copy
import datetime
import logging
import threading

import elasticsearch
import mock
import pytest
from elastalert import config
from elastalert.enhancements.drop_match_exception import DropMatchException
from elastalert.enhancements.test_enhancement import TestEnhancement
from elastalert.queries.elasticsearch_query import (
    ElasticsearchCountQuery,
    ElasticsearchQuery,
)
from elastalert.ruletypes import AnyRule, FrequencyRule
from elastalert.utils import util
from elastalert.utils.time import (
    dt_to_ts,
    dt_to_unix,
    dt_to_unixms,
    ts_to_dt,
    unix_to_dt,
)
from elastalert.utils.util import EAException, elasticsearch_client, ts_now
from elasticsearch.exceptions import ConnectionError, ElasticsearchException

START_TIMESTAMP = "2014-09-26T12:34:45Z"
END_TIMESTAMP = "2014-09-27T12:34:45Z"
START = ts_to_dt(START_TIMESTAMP)
END = ts_to_dt(END_TIMESTAMP)


def _set_hits(client, hits):
    res = {"hits": {"total": {"value": len(hits)}, "hits": hits}}
    client.search.return_value = res


def call_run_query(es, rule, hits=[], start=START, end=END):
    es.search.return_value = {"hits": {"total": {"value": len(hits)}, "hits": hits}}
    query = ElasticsearchQuery(rule, rule["type"].add_data, {}, es)
    query.build_query()
    query.run_query(start, end)

    return query


def generate_hits(timestamps, **kwargs):
    hits = []
    for i, ts in enumerate(timestamps):
        data = {
            "_id": "id{}".format(i),
            "_source": {"@timestamp": ts},
            "_type": "logs",
            "_index": "idx",
        }
        for key, item in kwargs.items():
            data["_source"][key] = item
        # emulate process_hits(), add metadata to _source
        for field in ["_id", "_type", "_index"]:
            data["_source"][field] = data[field]
        hits.append(data)
    return hits


def assert_alerts(ea_inst, calls):
    """ Takes a list of lists of timestamps. Asserts that an alert was called for each list, containing those timestamps. """
    assert ea_inst.rules["testrule"]["alert"][0].alert.call_count == len(calls)
    for call_num, call_args in enumerate(
        ea_inst.rules["testrule"]["alert"][0].alert.call_args_list
    ):
        assert not any(
            [match["@timestamp"] not in calls[call_num] for match in call_args[0][0]]
        )
        assert len(call_args[0][0]) == len(calls[call_num])


def test_starttime(ea):
    invalid = ["2014-13-13", "2014-11-24T30:00:00", "Not A Timestamp"]
    for ts in invalid:
        with pytest.raises((TypeError, ValueError)):
            ts_to_dt(ts)


def test_init_rule(ea):
    # Simulate state of a rule just loaded from a file
    ea.rules["testrule"]["minimum_starttime"] = datetime.datetime.now()
    new_rule = copy.copy(ea.rules["testrule"])
    list(
        map(
            new_rule.pop,
            [
                "agg_matches",
                "current_aggregate_id",
                "processed_hits",
                "minimum_starttime",
            ],
        )
    )

    # Properties are copied from ea.rules["testrule"]
    ea.rules["testrule"]["starttime"] = "2014-01-02T00:11:22"
    ea.rules["testrule"]["processed_hits"] = ["abcdefg"]
    new_rule = ea.init_rule(new_rule, False, "testrule")
    for prop in [
        "starttime",
        "agg_matches",
        "current_aggregate_id",
        "processed_hits",
        "minimum_starttime",
        "run_every",
    ]:
        assert new_rule[prop] == ea.rules["testrule"][prop]

    # Properties are fresh
    new_rule = ea.init_rule(new_rule, True)
    new_rule.pop("starttime")
    assert "starttime" not in new_rule
    assert new_rule["processed_hits"] == {}

    # Assert run_every is unique
    new_rule["run_every"] = datetime.timedelta(seconds=17)
    new_rule = ea.init_rule(new_rule, True)
    assert new_rule["run_every"] == datetime.timedelta(seconds=17)


def test_query(ea):
    rule = ea.rules["testrule"].copy()
    call_run_query(ea.es, rule)
    ea.es.search.assert_called_with(
        index="idx",
        body={
            "query": {
                "bool": {
                    "filter": [],
                    "must": {
                        "range": {
                            "@timestamp": {"gt": START_TIMESTAMP, "lte": END_TIMESTAMP}
                        }
                    },
                }
            },
            "sort": ["@timestamp"],
        },
        ignore_unavailable=True,
        size=ea.rules["testrule"]["max_query_size"],
        scroll=config._cfg.__dict__["scroll_keepalive"],
        _source_includes=["@timestamp"],
    )


def test_query_with_fields(ea):
    rule = ea.rules["testrule"].copy()
    rule["_source_enabled"] = False
    call_run_query(ea.es, rule)
    ea.es.search.assert_called_with(
        index="idx",
        body={
            "query": {
                "bool": {
                    "filter": [],
                    "must": {
                        "range": {
                            "@timestamp": {"gt": START_TIMESTAMP, "lte": END_TIMESTAMP}
                        }
                    },
                }
            },
            "sort": ["@timestamp"],
            "stored_fields": ["@timestamp"],
        },
        ignore_unavailable=True,
        size=ea.rules["testrule"]["max_query_size"],
        scroll=config._cfg.__dict__["scroll_keepalive"],
    )


def query_with_time(ea, time_func):
    rule = ea.rules["testrule"].copy()
    rule["timestamp_type"] = "unix"
    rule["dt_to_ts"] = time_func
    call_run_query(ea.es, rule)
    start_unix = time_func(START)
    end_unix = time_func(END)
    ea.es.search.assert_called_with(
        index="idx",
        body={
            "query": {
                "bool": {
                    "filter": [],
                    "must": {
                        "range": {"@timestamp": {"gt": start_unix, "lte": end_unix}}
                    },
                }
            },
            "sort": ["@timestamp"],
        },
        ignore_unavailable=True,
        size=ea.rules["testrule"]["max_query_size"],
        scroll=config._cfg.__dict__["scroll_keepalive"],
        _source_includes=["@timestamp"],
    )


def test_query_with_unix(ea):
    query_with_time(ea, dt_to_unix)


def test_query_with_unixms(ea):
    query_with_time(ea, dt_to_unixms)


def test_no_hits(ea):
    rule = ea.rules["testrule"].copy()
    call_run_query(ea.es, rule)
    assert rule["type"].add_data.call_count == 0


def test_no_terms_hits(ea):
    rule = ea.rules["testrule"].copy()
    rule["use_terms_query"] = True
    rule["query_key"] = "QWERTY"
    rule["doc_type"] = "uiop"
    call_run_query(ea.es, rule)
    assert rule["type"].add_terms_data.call_count == 0


def test_some_hits(ea):
    rule = ea.rules["testrule"].copy()

    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    call_run_query(ea.es, rule, hits)

    assert rule["type"].add_data.call_count == 1
    rule["type"].add_data.assert_called_with([x["_source"] for x in hits])


def test_some_hits_unix(ea):
    rule = ea.rules["testrule"].copy()
    rule["dt_to_ts"] = dt_to_unix
    rule["ts_to_dt"] = unix_to_dt

    hits = generate_hits([dt_to_unix(START), dt_to_unix(END)])
    call_run_query(ea.es, rule, hits)

    assert rule["type"].add_data.call_count == 1
    rule["type"].add_data.assert_called_with([x["_source"] for x in hits])


def _duplicate_hits_generator(timestamps, **kwargs):
    """Generator repeatedly returns identical hits dictionaries
    """
    while True:
        yield generate_hits(timestamps, **kwargs)


def test_duplicate_timestamps(ea):
    rule = ea.rules["testrule"].copy()

    hits = _duplicate_hits_generator([START_TIMESTAMP] * 3, blah="duplicate")
    query = call_run_query(
        ea.es, rule, next(hits), START, ts_to_dt("2014-01-01T00:00:00Z")
    )

    assert len(rule["type"].add_data.call_args_list[0][0][0]) == 3
    assert rule["type"].add_data.call_count == 1

    query.run_query(ts_to_dt("2014-01-01T00:00:00Z"), END)
    assert rule["type"].add_data.call_count == 1


def test_match(ea):
    rule = ea.rules["testrule"]
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    ea.es.search.return_value = {"hits": {"total": {"value": len(hits)}, "hits": hits}}
    rule["type"] = AnyRule(rule, es=ea.es)
    rule["initial_starttime"] = START
    with mock.patch.object(rule["type"], "is_silenced") as silenced:
        silenced.return_value = False
        rule["type"].run_rule(END)
    rule["alert"][0].alert.called_with({"@timestamp": END_TIMESTAMP})


@pytest.mark.skip(
    reason="This test does not work because garbage_collect will be called in run but run is mocked"
)
def test_run_rule_calls_garbage_collect(ea):
    start_time = "2014-09-26T00:00:00Z"
    # TODO frozen access
    config._cfg.__dict__["buffer_time"] = datetime.timedelta(hours=1)
    config._cfg.__dict__["buffer_time"] = datetime.timedelta(hours=1)
    config._cfg.__dict__["run_every"] = datetime.timedelta(hours=1)
    rule = ea.rules["testrule"].copy()
    rule["type"] = AnyRule(rule, es=ea.es)
    rule["initial_starttime"] = ts_to_dt(start_time)
    with mock.patch.object(ElasticsearchQuery, "run"), mock.patch.object(
        rule["type"], "is_silenced"
    ) as silenced, mock.patch.object(rule["type"], "garbage_collect") as collect:
        silenced.return_value = False
        end_time = "2014-09-26T12:00:00Z"
        rule["type"].run_rule(ts_to_dt(end_time))

    # Running ElastAlert every hour for 12 hours, we should see
    # self.garbage_collect called 12 times.
    assert collect.call_count == 12

    # The calls should be spaced 1 hour apart
    expected_calls = [
        ts_to_dt(start_time) + datetime.timedelta(hours=i) for i in range(1, 13)
    ]
    for e in expected_calls:
        collect.assert_any_call(e)


def run_rule_query_exception(ea, caplog):
    rule = ea.rules["testrule"]

    with caplog.at_level(logging.ERROR):
        ea.handle_rule_execution(rule)
        assert "Error running rule" in caplog.text

    # Assert neither add_data nor garbage_collect were called
    # and that starttime did not change
    assert rule.get("starttime") == START
    assert rule["type"].add_data.call_count == 0
    assert rule["type"].garbage_collect.call_count == 0
    assert rule["type"].add_count_data.call_count == 0


def test_query_exception(ea, caplog):
    rule_conf = ea.rules["testrule"]
    rule_conf["query_delay"] = datetime.timedelta(minutes=10)
    rule_conf["initial_starttime"] = START
    # Todo frozen access
    config._cfg.__dict__["args"] = None
    mock_es = mock.Mock()
    mock_es.search.side_effect = ElasticsearchException
    ea.rules["testrule"]["type"] = AnyRule(rule_conf, es=mock_es)
    ea.rules["testrule"]["type"].add_data = mock.Mock()
    ea.rules["testrule"]["type"].garbage_collect = mock.Mock()
    ea.rules["testrule"]["type"].add_count_data = mock.Mock()
    run_rule_query_exception(ea, caplog)


def test_query_exception_count_query(ea, caplog):
    rule_conf = ea.rules["testrule"]
    rule_conf["query_delay"] = datetime.timedelta(minutes=10)
    rule_conf["initial_starttime"] = START
    rule_conf["use_count_query"] = True
    rule_conf["doc_type"] = "blahblahblahblah"
    # TODO frozen access
    config._cfg.__dict__["args"] = None
    mock_es = mock.Mock()
    mock_es.count.side_effect = ElasticsearchException
    ea.rules["testrule"]["type"] = FrequencyRule(rule_conf, es=mock_es)
    ea.rules["testrule"]["type"].add_data = mock.Mock()
    ea.rules["testrule"]["type"].garbage_collect = mock.Mock()
    ea.rules["testrule"]["type"].add_count_data = mock.Mock()
    run_rule_query_exception(ea, caplog)


def test_match_with_module(ea):
    mod = TestEnhancement(ea.rules["testrule"])
    mod.process = mock.Mock()
    ea.rules["testrule"]["match_enhancements"] = [mod]
    test_match(ea)
    mod.process.assert_called()


def test_match_with_module_from_pending(ea):
    mod = TestEnhancement(ea.rules["testrule"])
    mod.process = mock.Mock()
    ea.rules["testrule"]["match_enhancements"] = [mod]
    ea.rules["testrule"].pop("aggregation")

    pending_alert = {
        "match_body": {"foo": "bar"},
        "rule_name": ea.rules["testrule"]["name"],
        "alert_time": START_TIMESTAMP,
        "@timestamp": START_TIMESTAMP,
    }
    # First call, return the pending alert, second, no associated aggregated alerts
    ea.writeback_es.search.side_effect = [
        {"hits": {"hits": [{"_id": "ABCD", "_index": "wb", "_source": pending_alert}]}},
        {"hits": {"hits": []}},
    ]

    ea.send_pending_alerts()
    assert mod.process.call_count == 0

    # If aggregation is set, enhancement IS called
    pending_alert = {
        "match_body": {"foo": "bar"},
        "rule_name": ea.rules["testrule"]["name"],
        "alert_time": START_TIMESTAMP,
        "@timestamp": START_TIMESTAMP,
    }
    ea.writeback_es.search.side_effect = [
        {"hits": {"hits": [{"_id": "ABCD", "_index": "wb", "_source": pending_alert}]}},
        {"hits": {"hits": []}},
        {"hits": {"hits": []}},
    ]
    ea.rules["testrule"]["aggregation"] = datetime.timedelta(minutes=10)
    ea.send_pending_alerts()
    assert mod.process.call_count == 1


def test_match_with_module_with_agg(ea):
    mod = TestEnhancement(ea.rules["testrule"])
    mod.process = mock.Mock()
    ea.rules["testrule"]["match_enhancements"] = [mod]
    ea.rules["testrule"]["aggregation"] = datetime.timedelta(minutes=15)
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    _set_hits(ea.rule_es, hits)
    ea.rules["testrule"]["type"].matches = [{"@timestamp": END}]
    ea.rules["testrule"]["initial_starttime"] = START
    with mock.patch("elastalert.elastalert.elasticsearch_client"):
        ea.testrule.run_rule(END)
    assert mod.process.call_count == 0


def test_match_with_enhancements_first(ea):
    mod = TestEnhancement(ea.rules["testrule"])
    mod.process = mock.Mock()
    ea.rules["testrule"]["match_enhancements"] = [mod]
    ea.rules["testrule"]["aggregation"] = datetime.timedelta(minutes=15)
    ea.rules["testrule"]["run_enhancements_first"] = True
    ea.rules["testrule"]["initial_starttime"] = START
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    _set_hits(ea.rule_es, hits)
    with mock.patch.object(
        ea.rules["testrule"]["type"], "add_aggregated_alert"
    ) as add_alert:
        ea.testrule.run_rule(END)
    mod.process.assert_called()
    assert add_alert.call_count == 2

    # Assert that dropmatchexception behaves properly
    mod.process = mock.MagicMock(side_effect=DropMatchException)
    ea.rules["testrule"]["type"].matches = [{"@timestamp": END}]
    ea.rules["testrule"]["initial_starttime"] = START
    with mock.patch.object(
        ea.rules["testrule"]["type"], "add_aggregated_alert"
    ) as add_alert:
        ea.testrule.run_rule(END)
    mod.process.assert_called()
    assert add_alert.call_count == 0


def test_agg_matchtime(ea):
    config._cfg.__dict__["max_aggregation"] = 1337
    hits_timestamps = [
        "2014-09-26T12:34:45",
        "2014-09-26T12:40:45",
        "2014-09-26T12:47:45",
    ]
    ea.testrule.add_match = mock.Mock()
    alerttime1 = dt_to_ts(ts_to_dt(hits_timestamps[0]) + datetime.timedelta(minutes=10))
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    _set_hits(ea.rule_es, hits)
    # Aggregate first two, query over full range
    ea.rules["testrule"]["aggregate_by_match_time"] = True
    ea.rules["testrule"]["aggregation"] = datetime.timedelta(minutes=10)
    ea.rules["testrule"]["type"].matches = [{"@timestamp": h} for h in hits_timestamps]
    ea.rules["testrule"]["initial_starttime"] = START
    ea.testrule.run_rule(END)

    # Assert that the three matches were added to Elasticsearch
    call1 = ea.rule_es.index.call_args_list[0][1]["body"]
    call2 = ea.rule_es.index.call_args_list[1][1]["body"]
    call3 = ea.rule_es.index.call_args_list[2][1]["body"]
    assert call1["match_body"]["@timestamp"] == "2014-09-26T12:34:45"
    assert not call1["alert_sent"]
    assert "aggregate_id" not in call1
    assert call1["alert_time"] == alerttime1

    assert call2["match_body"]["@timestamp"] == "2014-09-26T12:40:45"
    assert not call2["alert_sent"]
    assert call2["aggregate_id"] == "ABCD"

    assert call3["match_body"]["@timestamp"] == "2014-09-26T12:47:45"
    assert not call3["alert_sent"]
    assert "aggregate_id" not in call3

    # First call - Find all pending alerts (only entries without agg_id)
    # Second call - Find matches with agg_id == 'ABCD'
    # Third call - Find matches with agg_id == 'CDEF'
    ea.writeback_es.search.side_effect = [
        {
            "hits": {
                "hits": [
                    {"_id": "ABCD", "_index": "wb", "_source": call1},
                    {"_id": "CDEF", "_index": "wb", "_source": call3},
                ]
            }
        },
        {"hits": {"hits": [{"_id": "BCDE", "_index": "wb", "_source": call2}]}},
        {"hits": {"total": 0, "hits": []}},
    ]

    ea.send_pending_alerts()
    # Assert that current_es was refreshed from the aggregate rules
    assert_alerts(ea, [hits_timestamps[:2], hits_timestamps[2:]])

    call2 = ea.writeback_es.search.call_args_list[0][1]
    call3 = ea.writeback_es.search.call_args_list[1][1]
    call4 = ea.writeback_es.search.call_args_list[2][1]

    assert "alert_time" in call2["body"]["query"]["bool"]["filter"]["range"]
    assert call3["body"]["query"]["query_string"]["query"] == "aggregate_id:'ABCD'"
    assert call4["body"]["query"]["query_string"]["query"] == "aggregate_id:'CDEF'"
    assert call3["size"] == 1337


def test_agg_not_matchtime(ea):
    ea.max_aggregation = 1337
    hits_timestamps = [
        "2014-09-26T12:34:45",
        "2014-09-26T12:40:45",
        "2014-09-26T12:47:45",
    ]
    match_time = ts_to_dt("2014-09-26T12:55:00Z")
    ea.testrule.add_match = mock.Mock()
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    _set_hits(ea.rule_es, hits)
    # Aggregate first two, query over full range
    ea.rules["testrule"]["aggregation"] = datetime.timedelta(minutes=10)
    ea.rules["testrule"]["type"].matches = [{"@timestamp": h} for h in hits_timestamps]
    ea.rules["testrule"]["initial_starttime"] = START
    with mock.patch("elastalert.rule.ts_now", return_value=match_time):
        ea.testrule.run_rule(END)

    # Assert that the three matches were added to Elasticsearch
    call1 = ea.rule_es.index.call_args_list[0][1]["body"]
    call2 = ea.rule_es.index.call_args_list[1][1]["body"]
    call3 = ea.rule_es.index.call_args_list[2][1]["body"]

    assert call1["match_body"]["@timestamp"] == "2014-09-26T12:34:45"
    assert not call1["alert_sent"]
    assert "aggregate_id" not in call1
    assert call1["alert_time"] == dt_to_ts(match_time + datetime.timedelta(minutes=10))

    assert call2["match_body"]["@timestamp"] == "2014-09-26T12:40:45"
    assert not call2["alert_sent"]
    assert call2["aggregate_id"] == "ABCD"

    assert call3["match_body"]["@timestamp"] == "2014-09-26T12:47:45"
    assert not call3["alert_sent"]
    assert call3["aggregate_id"] == "ABCD"


def test_agg_cron(ea):
    ea.testrule.add_match = mock.Mock()
    ea.max_aggregation = 1337
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    _set_hits(ea.rule_es, hits)
    alerttime1 = dt_to_ts(ts_to_dt("2014-09-26T12:46:00"))
    alerttime2 = dt_to_ts(ts_to_dt("2014-09-26T13:04:00"))

    with mock.patch("elastalert.elastalert.croniter.get_next") as mock_ts:
        # Aggregate first two, query over full range
        mock_ts.side_effect = [
            dt_to_unix(ts_to_dt("2014-09-26T12:46:00")),
            dt_to_unix(ts_to_dt("2014-09-26T13:04:00")),
        ]
        ea.rules["testrule"]["aggregation"] = {"schedule": "*/5 * * * *"}
        ea.rules["testrule"]["initial_starttime"] = START
        hits_timestamps = [
            "2014-09-26T12:34:45",
            "2014-09-26T12:40:45",
            "2014-09-26T12:47:45",
        ]
        ea.rules["testrule"]["type"].matches = [
            {"@timestamp": h} for h in hits_timestamps
        ]
        ea.testrule.run_rule(END)

    # Assert that the three matches were added to Elasticsearch
    call1 = ea.rule_es.index.call_args_list[0][1]["body"]
    call2 = ea.rule_es.index.call_args_list[1][1]["body"]
    call3 = ea.rule_es.index.call_args_list[2][1]["body"]

    assert call1["match_body"]["@timestamp"] == "2014-09-26T12:34:45"
    assert not call1["alert_sent"]
    assert "aggregate_id" not in call1
    assert call1["alert_time"] == alerttime1

    assert call2["match_body"]["@timestamp"] == "2014-09-26T12:40:45"
    assert not call2["alert_sent"]
    assert call2["aggregate_id"] == "ABCD"

    assert call3["match_body"]["@timestamp"] == "2014-09-26T12:47:45"
    assert call3["alert_time"] == alerttime2
    assert not call3["alert_sent"]
    assert "aggregate_id" not in call3


def test_agg_no_writeback_connectivity(ea):
    ea.testrule.add_match = mock.Mock()
    """ Tests that if writeback_es throws an exception, the matches will be added to 'agg_matches' and when
    run again, that they will be passed again to add_aggregated_alert """
    _set_hits(ea.rule_es, [])
    ea.rules["testrule"]["aggregation"] = datetime.timedelta(minutes=10)
    hit1, hit2, hit3 = (
        "2014-09-26T12:34:45",
        "2014-09-26T12:40:45",
        "2014-09-26T12:47:45",
    )
    ea.rules["testrule"]["type"].matches = [
        {"@timestamp": hit1},
        {"@timestamp": hit2},
        {"@timestamp": hit3},
    ]
    ea.rules["testrule"]["initial_starttime"] = START
    ea.rule_es.index.side_effect = elasticsearch.exceptions.ElasticsearchException(
        "Nope"
    )
    with mock.patch.object(ea, "find_pending_aggregate_alert", return_value=None):
        ea.testrule.run_rule(END)

    assert ea.rules["testrule"]["agg_matches"] == [
        {"@timestamp": hit1, "num_hits": 0, "num_matches": 3},
        {"@timestamp": hit2, "num_hits": 0, "num_matches": 3},
        {"@timestamp": hit3, "num_hits": 0, "num_matches": 3},
    ]

    ea.rule_es.search.return_value = {"hits": {"total": 0, "hits": []}}
    with mock.patch.object(
        ea.rules["testrule"]["type"], "add_aggregated_alert"
    ) as add_aggregated_alert:
        with mock.patch.object(ElasticsearchQuery, "get_hits"):
            ea.rules["testrule"]["initial_starttime"] = START
            ea.testrule.run_rule(END)

    add_aggregated_alert.assert_any_call(
        {"@timestamp": hit1, "num_hits": 0, "num_matches": 3}, ea.rules["testrule"]
    )
    add_aggregated_alert.assert_any_call(
        {"@timestamp": hit2, "num_hits": 0, "num_matches": 3}, ea.rules["testrule"]
    )
    add_aggregated_alert.assert_any_call(
        {"@timestamp": hit3, "num_hits": 0, "num_matches": 3}, ea.rules["testrule"]
    )


def test_agg_with_aggregation_key(ea):
    ea.testrule.add_match = mock.Mock()
    config._cfg.__dict__["max_aggregation"] = 1337
    hits_timestamps = [
        "2014-09-26T12:34:45",
        "2014-09-26T12:40:45",
        "2014-09-26T12:43:45",
    ]
    match_time = ts_to_dt("2014-09-26T12:45:00Z")
    _set_hits(ea.rule_es, [])
    with mock.patch("elastalert.rule.ts_now", return_value=match_time):
        ea.rules["testrule"]["aggregation"] = datetime.timedelta(minutes=10)
        ea.rules["testrule"]["type"].matches = [
            {"@timestamp": h} for h in hits_timestamps
        ]
        # Hit1 and Hit3 should be aggregated together, since they have same
        # query_key value
        ea.rules["testrule"]["type"].matches[0]["key"] = "Key Value 1"
        ea.rules["testrule"]["type"].matches[1]["key"] = "Key Value 2"
        ea.rules["testrule"]["type"].matches[2]["key"] = "Key Value 1"
        ea.rules["testrule"]["aggregation_key"] = "key"
        ea.rules["testrule"]["initial_starttime"] = START
        ea.testrule.run_rule(END)

    # Assert that the three matches were added to elasticsearch
    call1 = ea.rule_es.index.call_args_list[0][1]["body"]
    call2 = ea.rule_es.index.call_args_list[1][1]["body"]
    call3 = ea.rule_es.index.call_args_list[2][1]["body"]
    assert call1["match_body"]["key"] == "Key Value 1"
    assert not call1["alert_sent"]
    assert "aggregate_id" not in call1
    assert "aggregation_key" in call1
    assert call1["aggregation_key"] == "Key Value 1"
    assert call1["alert_time"] == dt_to_ts(match_time + datetime.timedelta(minutes=10))

    assert call2["match_body"]["key"] == "Key Value 2"
    assert not call2["alert_sent"]
    assert "aggregate_id" not in call2
    assert "aggregation_key" in call2
    assert call2["aggregation_key"] == "Key Value 2"
    assert call2["alert_time"] == dt_to_ts(match_time + datetime.timedelta(minutes=10))

    assert call3["match_body"]["key"] == "Key Value 1"
    assert not call3["alert_sent"]
    # Call3 should have it's aggregate_id set to call1's _id
    # It should also have the same alert_time as call1
    assert call3["aggregate_id"] == "ABCD"
    assert "aggregation_key" in call3
    assert call3["aggregation_key"] == "Key Value 1"
    assert call3["alert_time"] == dt_to_ts(match_time + datetime.timedelta(minutes=10))

    # First call - Find all pending alerts (only entries without agg_id)
    # Second call - Find matches with agg_id == 'ABCD'
    # Third call - Find matches with agg_id == 'CDEF'
    ea.writeback_es.search.side_effect = [
        {
            "hits": {
                "hits": [
                    {"_id": "ABCD", "_index": "wb", "_source": call1},
                    {"_id": "CDEF", "_index": "wb", "_source": call2},
                ]
            }
        },
        {"hits": {"hits": [{"_id": "BCDE", "_index": "wb", "_source": call3}]}},
        {"hits": {"total": 0, "hits": []}},
    ]

    ea.send_pending_alerts()
    # Assert that current_es was refreshed from the aggregate rules
    assert_alerts(ea, [[hits_timestamps[0], hits_timestamps[2]], [hits_timestamps[1]]])

    call2 = ea.writeback_es.search.call_args_list[0][1]
    call3 = ea.writeback_es.search.call_args_list[1][1]
    call4 = ea.writeback_es.search.call_args_list[2][1]

    assert "alert_time" in call2["body"]["query"]["bool"]["filter"]["range"]
    assert call3["body"]["query"]["query_string"]["query"] == "aggregate_id:'ABCD'"
    assert call4["body"]["query"]["query_string"]["query"] == "aggregate_id:'CDEF'"
    assert call3["size"] == 1337


def test_silence(ea):
    # Silence test rule for 4 hours
    config._cfg.__dict__[
        "args"
    ].rule = "test_rule.yaml"  # Not a real name, just has to be set
    config._cfg.__dict__["args"].silence = "hours=4"
    rule_config = ea.rules["testrule"].copy()
    rule_config["initial_starttime"] = START

    # Overwrite rule so is_silenced is available
    new_rule = AnyRule(rule_config, es=ea.rule_es)
    ea.rules["testrule"]["type"] = new_rule
    ea.silence()

    # Don't alert even with a match
    match = [{"@timestamp": "2014-11-17T00:00:00"}]
    rule_config["type"].matches = match
    _set_hits(ea.rule_es, [])
    new_rule.run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 0

    # Mock ts_now() to +5 hours, alert on match
    match = [{"@timestamp": "2014-11-17T00:00:00"}]
    new_rule.matches = match
    with mock.patch("elastalert.rule.ts_now") as mock_ts:
        # Converted twice to add tzinfo
        mock_ts.return_value = ts_to_dt(
            dt_to_ts(datetime.datetime.utcnow() + datetime.timedelta(hours=5))
        )
        new_rule.run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 1


def test_compound_query_key(ea):
    rule = ea.rules["testrule"].copy()
    rule["query_key"] = "this,that,those"
    rule["compound_query_key"] = ["this", "that", "those"]
    hits = generate_hits(
        [START_TIMESTAMP, END_TIMESTAMP], this="abc", that="☃", those=4
    )

    call_run_query(ea.rule_es, rule, hits)
    call_args = rule["type"].add_data.call_args_list[0]
    assert "this,that,those" in call_args[0][0][0]
    assert call_args[0][0][0]["this,that,those"] == "abc, ☃, 4"


def test_silence_query_key(ea):
    # Silence test rule for 4 hours
    config._cfg.__dict__[
        "args"
    ].rule = "test_rule.yaml"  # Not a real name, just has to be set
    config._cfg.__dict__["args"].silence = "hours=4"
    rule_config = ea.rules["testrule"].copy()
    rule_config["initial_starttime"] = START

    # Overwrite rule so is_silenced is available
    new_rule = AnyRule(rule_config, es=ea.rule_es)
    ea.rules["testrule"]["type"] = new_rule

    ea.silence("testrule.qlo")

    # Don't alert even with a match
    match = [{"@timestamp": "2014-11-17T00:00:00", "username": "qlo"}]
    ea.rules["testrule"]["type"].rule_config["query_key"] = "username"
    ea.rules["testrule"]["type"].matches = match
    _set_hits(ea.rule_es, [])

    ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 0

    # If there is a new record with a different value for the query_key, we
    # should get an alert
    match = [{"@timestamp": "2014-11-17T00:00:01", "username": "dpopes"}]
    ea.rules["testrule"]["type"].matches = match
    ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 1

    # Mock ts_now() to +5 hours, alert on match
    match = [{"@timestamp": "2014-11-17T00:00:00", "username": "qlo"}]
    ea.rules["testrule"]["type"].matches = match
    with mock.patch("elastalert.rule.ts_now") as mock_ts:
        # Converted twice to add tzinfo
        mock_ts.return_value = ts_to_dt(
            dt_to_ts(datetime.datetime.utcnow() + datetime.timedelta(hours=5))
        )
        ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 2


def test_realert(ea):
    rule_config = ea.rules["testrule"].copy()
    rule_config["initial_starttime"] = START

    # Overwrite rule so is_silenced is available
    new_rule = AnyRule(rule_config, es=ea.rule_es)
    ea.rules["testrule"]["type"] = new_rule

    hits = ["2014-09-26T12:35:%sZ" % (x) for x in range(60)]
    matches = [{"@timestamp": x} for x in hits]
    _set_hits(ea.rule_es, [])
    ea.rules["testrule"]["type"].rule_config["realert"] = datetime.timedelta(seconds=50)
    ea.rules["testrule"]["type"].matches = matches
    ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 1

    # Doesn't alert again
    matches = [{"@timestamp": x} for x in hits]
    ea.rules["testrule"]["type"].run_rule(END)
    ea.rules["testrule"]["type"].matches = matches
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 1

    # mock ts_now() to past the realert time
    matches = [{"@timestamp": hits[0]}]
    with mock.patch("elastalert.rule.ts_now") as mock_ts:
        # mock_ts is converted twice to add tzinfo
        mock_ts.return_value = ts_to_dt(
            dt_to_ts(datetime.datetime.utcnow() + datetime.timedelta(minutes=10))
        )
        ea.rules["testrule"]["type"].matches = matches
        ea.rules["testrule"]["type"].run_rule(END)
        assert ea.rules["testrule"]["alert"][0].alert.call_count == 2


def test_realert_with_query_key(ea):
    rule_config = ea.rules["testrule"].copy()
    rule_config["initial_starttime"] = START

    # Overwrite rule so is_silenced is available
    new_rule = AnyRule(rule_config, es=ea.rule_es)
    ea.rules["testrule"]["type"] = new_rule
    _set_hits(ea.rule_es, [])

    ea.rules["testrule"]["type"].rule_config["query_key"] = "username"
    ea.rules["testrule"]["type"].rule_config["realert"] = datetime.timedelta(minutes=10)

    # Alert and silence username: qlo
    match = [{"@timestamp": "2014-11-17T00:00:00", "username": "qlo"}]
    ea.rules["testrule"]["type"].matches = match
    ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 1

    # Dont alert again for same username
    match = [{"@timestamp": "2014-11-17T00:05:00", "username": "qlo"}]
    ea.rules["testrule"]["type"].matches = match
    ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 1

    # Do alert with a different value
    match = [{"@timestamp": "2014-11-17T00:05:00", "username": ""}]
    ea.rules["testrule"]["type"].matches = match
    ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 2

    # Alert with query_key missing
    match = [{"@timestamp": "2014-11-17T00:05:00"}]
    ea.rules["testrule"]["type"].matches = match
    ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 3

    # Still alert with a different value
    match = [{"@timestamp": "2014-11-17T00:05:00", "username": "ghengis_khan"}]
    ea.rules["testrule"]["type"].matches = match
    ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 4


def test_realert_with_nested_query_key(ea):
    rule_config = ea.rules["testrule"].copy()
    rule_config["initial_starttime"] = START

    # Overwrite rule so is_silenced is available
    new_rule = AnyRule(rule_config, es=ea.rule_es)
    ea.rules["testrule"]["type"] = new_rule
    _set_hits(ea.rule_es, [])

    ea.rules["testrule"]["type"].rule_config["query_key"] = "user.name"
    ea.rules["testrule"]["type"].rule_config["realert"] = datetime.timedelta(minutes=10)

    # Alert and silence username: qlo
    match = [{"@timestamp": "2014-11-17T00:00:00", "user": {"name": "qlo"}}]
    ea.rules["testrule"]["type"].matches = match
    ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 1

    # Dont alert again for same username
    match = [{"@timestamp": "2014-11-17T00:05:00", "user": {"name": "qlo"}}]
    ea.rules["testrule"]["type"].matches = match
    ea.rules["testrule"]["type"].run_rule(END)
    assert ea.rules["testrule"]["alert"][0].alert.call_count == 1


def test_count(ea):
    rule_config = ea.rules["testrule"].copy()
    rule_config["initial_starttime"] = START

    rule_config["use_count_query"] = True
    rule_config["doc_type"] = "doctype"
    # Overwrite rule so is_silenced is available
    new_rule = FrequencyRule(rule_config, es=ea.rule_es)
    ea.rules["testrule"]["type"] = new_rule
    _set_hits(ea.rule_es, [])

    with mock.patch.object(ElasticsearchCountQuery, "get_hits") as mock_hits:
        ea.rules["testrule"]["type"].run_rule(END)

    # Assert that es.count is run against every run_every timeframe between
    # START and END
    start = START
    query = {
        "query": {
            "filtered": {
                "filter": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "lte": END_TIMESTAMP,
                                        "gt": START_TIMESTAMP,
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    }
    while END - start > ea.run_every:
        end = start + ea.run_every
        query["query"]["filtered"]["filter"]["bool"]["must"][0]["range"]["@timestamp"][
            "lte"
        ] = dt_to_ts(end)
        query["query"]["filtered"]["filter"]["bool"]["must"][0]["range"]["@timestamp"][
            "gt"
        ] = dt_to_ts(start)
        mock_hits.assert_any_call(start, end)
        start = start + ea.run_every


# TODO test get_segment_size directly as it makes more sense
def test_rule_default(ea):
    _set_hits(ea.rule_es, [])
    ea.rules["testrule"]["initial_starttime"] = START

    with mock.patch.object(ElasticsearchQuery, "get_hits") as mock_hits:
        ea.rules["testrule"]["type"].run_rule(END)

    # Assert that es.count is run against every run_every timeframe between
    # START and END
    start = START
    query = {
        "query": {
            "filtered": {
                "filter": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "lte": END_TIMESTAMP,
                                        "gt": START_TIMESTAMP,
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    }
    segment = config.CFG().buffer_time
    while END - start > segment:
        end = start + segment
        query["query"]["filtered"]["filter"]["bool"]["must"][0]["range"]["@timestamp"][
            "lte"
        ] = dt_to_ts(end)
        query["query"]["filtered"]["filter"]["bool"]["must"][0]["range"]["@timestamp"][
            "gt"
        ] = dt_to_ts(start)
        mock_hits.assert_any_call(start, end)
        start = start + segment


def test_get_starttime(ea):
    endtime = "2015-01-01T00:00:00Z"

    mock_es = mock.Mock()
    mock_es.search.return_value = {
        "hits": {"hits": [{"_source": {"endtime": endtime}}]}
    }
    mock_es.info.return_value = {"version": {"number": "2.0"}}

    # 4 days old, will return endtime
    with mock.patch("elastalert.utils.util.ts_now") as mock_ts, mock.patch(
        "elastalert.utils.util.elasticsearch_client"
    ) as client:
        client.return_value = mock_es
        mock_ts.return_value = ts_to_dt("2015-01-05T00:00:00Z")
        start_time = util.get_starttime(ea.rules["testrule"])
        assert ts_to_dt(endtime) == start_time

    # 10 days old, will return None
    with mock.patch("elastalert.utils.util.ts_now") as mock_ts, mock.patch(
        "elastalert.utils.util.elasticsearch_client"
    ) as client:
        client.return_value = mock_es
        mock_ts.return_value = ts_to_dt(
            "2015-01-11T00:00:00Z"
        )  # 10 days ahead of the endtime
        start_time = util.get_starttime(ea.rules["testrule"])
        assert start_time is None


@pytest.mark.skip(reason="Starttime has moved to the query")
def test_set_starttime(ea):
    # standard query, no starttime, no last run
    end = ts_to_dt("2014-10-10T10:10:10")
    with mock.patch.object(ea, "get_starttime") as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules["testrule"], end)
        assert mock_gs.call_count == 1
    assert ea.rules["testrule"]["starttime"] == end - ea.buffer_time

    # Standard query, no starttime, rule specific buffer_time
    ea.rules["testrule"].pop("starttime")
    ea.rules["testrule"]["buffer_time"] = datetime.timedelta(minutes=37)
    with mock.patch.object(ea, "get_starttime") as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules["testrule"], end)
        assert mock_gs.call_count == 1
    assert ea.rules["testrule"]["starttime"] == end - datetime.timedelta(minutes=37)
    ea.rules["testrule"].pop("buffer_time")

    # Standard query, no starttime, last run
    ea.rules["testrule"].pop("starttime")
    with mock.patch.object(ea, "get_starttime") as mock_gs:
        mock_gs.return_value = ts_to_dt("2014-10-10T00:00:00")
        ea.set_starttime(ea.rules["testrule"], end)
        assert mock_gs.call_count == 1
    assert ea.rules["testrule"]["starttime"] == ts_to_dt("2014-10-10T00:00:00")

    # Standard query, no starttime, last run, assure buffer_time doesn't go past
    ea.rules["testrule"].pop("starttime")
    ea.rules["testrule"]["buffer_time"] = datetime.timedelta(weeks=1000)
    with mock.patch.object(ea, "get_starttime") as mock_gs:
        mock_gs.return_value = ts_to_dt("2014-10-09T00:00:00")
        # First call sets minumum_time
        ea.set_starttime(ea.rules["testrule"], end)
    # Second call uses buffer_time, but it goes past minimum
    ea.set_starttime(ea.rules["testrule"], end)
    assert ea.rules["testrule"]["starttime"] == ts_to_dt("2014-10-09T00:00:00")

    # Standard query, starttime
    ea.rules["testrule"].pop("buffer_time")
    ea.rules["testrule"].pop("minimum_starttime")
    with mock.patch.object(ea, "get_starttime") as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules["testrule"], end)
        assert mock_gs.call_count == 0
    assert ea.rules["testrule"]["starttime"] == end - ea.buffer_time

    # Count query, starttime, no previous endtime
    ea.rules["testrule"]["use_count_query"] = True
    ea.rules["testrule"]["doc_type"] = "blah"
    with mock.patch.object(ea, "get_starttime") as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules["testrule"], end)
        assert mock_gs.call_count == 0
    assert ea.rules["testrule"]["starttime"] == end - ea.run_every
    ea.rules["testrule"]["initial_starttime"] = START

    # Count query, with previous endtime
    with mock.patch("elastalert.elastalert.elasticsearch_client"), mock.patch.object(
        ea, "get_hits_count"
    ):
        ea.testrule.run_rule(END)
    ea.set_starttime(ea.rules["testrule"], end)
    assert ea.rules["testrule"]["starttime"] == END

    # buffer_time doesn't go past previous endtime
    ea.rules["testrule"].pop("use_count_query")
    ea.rules["testrule"]["previous_endtime"] = end - ea.buffer_time * 2
    ea.set_starttime(ea.rules["testrule"], end)
    assert ea.rules["testrule"]["starttime"] == ea.rules["testrule"]["previous_endtime"]

    # Make sure starttime is updated if previous_endtime isn't used
    ea.rules["testrule"]["previous_endtime"] = end - ea.buffer_time / 2
    ea.rules["testrule"]["starttime"] = ts_to_dt("2014-10-09T00:00:01")
    ea.set_starttime(ea.rules["testrule"], end)
    assert ea.rules["testrule"]["starttime"] == end - ea.buffer_time

    # scan_entire_timeframe
    ea.rules["testrule"].pop("previous_endtime")
    ea.rules["testrule"].pop("starttime")
    ea.rules["testrule"]["timeframe"] = datetime.timedelta(days=3)
    ea.rules["testrule"]["scan_entire_timeframe"] = True
    with mock.patch.object(ea, "get_starttime") as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules["testrule"], end)
    assert ea.rules["testrule"]["starttime"] == end - datetime.timedelta(days=3)


def test_rule_changes(ea):
    ea.rule_hashes = {"rules/rule1.yaml": "ABC", "rules/rule2.yaml": "DEF"}
    run_every = datetime.timedelta(seconds=1)
    ea.rules = {
        rule["rule_file"]: ea.init_rule(rule, True)
        for rule in [
            {
                "rule_file": "rules/rule1.yaml",
                "identifier": "rules/rule1.yaml",
                "name": "rule1",
                "filter": [],
                "run_every": run_every,
            },
            {
                "rule_file": "rules/rule2.yaml",
                "identifier": "rules/rule2.yaml",
                "name": "rule2",
                "filter": [],
                "run_every": run_every,
            },
        ]
    }
    ea.rules["rules/rule2.yaml"]["processed_hits"] = ["save me"]
    new_hashes = {
        "rules/rule1.yaml": "ABC",
        "rules/rule3.yaml": "XXX",
        "rules/rule2.yaml": "!@#$",
    }

    with mock.patch.object(ea.rules_loader, "get_hashes") as mock_hashes:
        with mock.patch.object(ea.rules_loader, "load_rule") as mock_load:
            mock_load.side_effect = [
                {
                    "filter": [],
                    "name": "rule2",
                    "rule_file": "rules/rule2.yaml",
                    "identifier": "rules/rule2.yaml",
                    "run_every": run_every,
                },
                {
                    "filter": [],
                    "name": "rule3",
                    "rule_file": "rules/rule3.yaml",
                    "identifier": "rules/rule3.yaml",
                    "run_every": run_every,
                },
            ]
            mock_hashes.return_value = new_hashes
            ea.handle_config_change()

    # All 3 rules still exist
    assert ea.rules["rules/rule1.yaml"]["name"] == "rule1"
    assert ea.rules["rules/rule2.yaml"]["name"] == "rule2"
    assert ea.rules["rules/rule2.yaml"]["processed_hits"] == ["save me"]
    assert ea.rules["rules/rule3.yaml"]["name"] == "rule3"

    # Assert 2 and 3 were reloaded
    assert mock_load.call_count == 2
    mock_load.assert_any_call("rules/rule2.yaml")
    mock_load.assert_any_call("rules/rule3.yaml")

    # A new rule with a conflicting name wont load
    new_hashes = copy.copy(new_hashes)
    new_hashes.update({"rules/rule4.yaml": "asdf"})
    with mock.patch.object(ea.rules_loader, "get_hashes") as mock_hashes:
        with mock.patch.object(ea.rules_loader, "load_rule") as mock_load:
            with mock.patch.object(ea, "send_notification_email") as mock_send:
                mock_load.return_value = {
                    "filter": [],
                    "name": "rule3",
                    "new": "stuff",
                    "rule_file": "rules/rule3.yaml",
                    "run_every": run_every,
                    "identifier": "rules/rule3.yaml",
                }
                mock_hashes.return_value = new_hashes
                ea.handle_config_change()
                mock_send.assert_called_once_with(
                    exception=mock.ANY, rule_file="rules/rule4.yaml"
                )
    assert len(ea.rules) == 3
    assert not any(["new" in rule for rule in ea.rules])

    # A new rule with is_enabled=False wont load
    new_hashes = copy.copy(new_hashes)
    new_hashes.update({"rules/rule4.yaml": "asdf"})
    with mock.patch.object(ea.rules_loader, "get_hashes") as mock_hashes:
        with mock.patch.object(ea.rules_loader, "load_rule") as mock_load:
            mock_load.return_value = {
                "filter": [],
                "name": "rule4",
                "new": "stuff",
                "is_enabled": False,
                "rule_file": "rules/rule4.yaml",
                "identifier": "rules/rule4.yaml",
                "run_every": run_every,
            }
            mock_hashes.return_value = new_hashes
            ea.handle_config_change()
    assert len(ea.rules) == 3
    assert not any(["new" in rule for rule in ea.rules])

    # An old rule which didn't load gets reloaded
    new_hashes = copy.copy(new_hashes)
    new_hashes["rules/rule4.yaml"] = "qwerty"
    with mock.patch.object(ea.rules_loader, "get_hashes") as mock_hashes:
        with mock.patch.object(ea.rules_loader, "load_rule") as mock_load:
            mock_load.return_value = {
                "filter": [],
                "name": "rule4",
                "new": "stuff",
                "rule_file": "rules/rule4.yaml",
                "run_every": run_every,
                "identifier": "rules/rule4.yaml",
            }
            mock_hashes.return_value = new_hashes
            ea.handle_config_change()
    assert len(ea.rules) == 4

    # Disable a rule by removing the file
    new_hashes.pop("rules/rule4.yaml")
    with mock.patch.object(ea.rules_loader, "get_hashes") as mock_hashes:
        with mock.patch.object(ea.rules_loader, "load_rule") as mock_load:
            mock_load.return_value = {
                "filter": [],
                "name": "rule4",
                "new": "stuff",
                "rule_file": "rules/rule4.yaml",
                "run_every": run_every,
                "identifier": "rules/rule4.yaml",
            }
            mock_hashes.return_value = new_hashes
            ea.handle_config_change()
    ea.scheduler.remove_job.assert_called_with(job_id="rule4")


def test_strf_index(ea):
    """ Test that the get_index function properly generates indexes spanning days """
    ea.rules["testrule"]["index"] = "logstash-%Y.%m.%d"
    ea.rules["testrule"]["use_strftime_index"] = True

    # Test formatting with times
    start = ts_to_dt("2015-01-02T12:34:45Z")
    end = ts_to_dt("2015-01-02T16:15:14Z")
    assert ea.get_index(ea.rules["testrule"], start, end) == "logstash-2015.01.02"
    end = ts_to_dt("2015-01-03T01:02:03Z")
    assert set(ea.get_index(ea.rules["testrule"], start, end).split(",")) == {
        "logstash-2015.01.02",
        "logstash-2015.01.03",
    }

    # Test formatting for wildcard
    assert ea.get_index(ea.rules["testrule"]) == "logstash-*"
    ea.rules["testrule"]["index"] = "logstash-%Y.%m"
    assert ea.get_index(ea.rules["testrule"]) == "logstash-*"
    ea.rules["testrule"]["index"] = "logstash-%Y.%m-stuff"
    assert ea.get_index(ea.rules["testrule"]) == "logstash-*-stuff"


def test_count_keys(ea):
    ea.rules["testrule"]["timeframe"] = datetime.timedelta(minutes=60)
    ea.rules["testrule"]["top_count_keys"] = ["this", "that"]
    ea.rules["testrule"]["type"].matches = {"@timestamp": END}
    ea.rules["testrule"]["doc_type"] = "blah"
    buckets = [
        {
            "aggregations": {
                "filtered": {
                    "counts": {
                        "buckets": [
                            {"key": "a", "doc_count": 10},
                            {"key": "b", "doc_count": 5},
                        ]
                    }
                }
            }
        },
        {
            "aggregations": {
                "filtered": {
                    "counts": {
                        "buckets": [
                            {"key": "d", "doc_count": 10},
                            {"key": "c", "doc_count": 12},
                        ]
                    }
                }
            }
        },
    ]
    ea.thread_data.current_es.deprecated_search.side_effect = buckets
    counts = ea.get_top_counts(ea.rules["testrule"], START, END, ["this", "that"])
    calls = ea.thread_data.current_es.deprecated_search.call_args_list
    assert calls[0][1]["search_type"] == "count"
    assert calls[0][1]["body"]["aggs"]["filtered"]["aggs"]["counts"]["terms"] == {
        "field": "this",
        "size": 5,
        "min_doc_count": 1,
    }
    assert counts["top_events_this"] == {"a": 10, "b": 5}
    assert counts["top_events_that"] == {"d": 10, "c": 12}


def test_exponential_realert(ea):
    ea.rules["testrule"]["exponential_realert"] = datetime.timedelta(
        days=1
    )  # 1 day ~ 10 * 2**13 seconds
    ea.rules["testrule"]["realert"] = datetime.timedelta(seconds=10)

    until = ts_to_dt("2015-03-24T00:00:00")
    ts5s = until + datetime.timedelta(seconds=5)
    ts15s = until + datetime.timedelta(seconds=15)
    ts1m = until + datetime.timedelta(minutes=1)
    ts5m = until + datetime.timedelta(minutes=5)
    ts4h = until + datetime.timedelta(hours=4)

    test_values = [
        (ts5s, until, 0),  # Exp will increase to 1, 10*2**0 = 10s
        (ts15s, until, 0),  # Exp will stay at 0, 10*2**0 = 10s
        (ts15s, until, 1),  # Exp will increase to 2, 10*2**1 = 20s
        (ts1m, until, 2),  # Exp will decrease to 1, 10*2**2 = 40s
        (ts1m, until, 3),  # Exp will increase to 4, 10*2**3 = 1m20s
        (ts5m, until, 1),  # Exp will lower back to 0, 10*2**1 = 20s
        (ts4h, until, 9),  # Exp will lower back to 0, 10*2**9 = 1h25m
        (ts4h, until, 10),  # Exp will lower back to 9, 10*2**10 = 2h50m
        (ts4h, until, 11),
    ]  # Exp will increase to 12, 10*2**11 = 5h
    results = (1, 0, 2, 1, 4, 0, 0, 9, 12)
    next_res = iter(results)
    for args in test_values:
        ea.silence_cache[ea.rules["testrule"]["name"]] = (args[1], args[2])
        next_alert, exponent = ea.next_alert_time(
            ea.rules["testrule"], ea.rules["testrule"]["name"], args[0]
        )
        assert exponent == next(next_res)


def test_wait_until_responsive(ea):
    """Unblock as soon as ElasticSearch becomes responsive."""

    # Takes a while before becoming responsive.
    ea.es.indices.exists.side_effect = [
        ConnectionError(),  # ES is not yet responsive.
        False,  # index does not yet exist.
        True,
    ]

    clock = mock.MagicMock()
    clock.side_effect = [0.0, 1.0, 2.0, 3.0, 4.0]
    timeout = datetime.timedelta(seconds=3.5)
    with mock.patch("time.sleep") as sleep:
        ea.wait_until_responsive(timeout=timeout, clock=clock)

    # Sleep as little as we can.
    sleep.mock_calls == [mock.call(1.0)]


def test_wait_until_responsive_timeout_es_not_available(ea, capsys):
    """Bail out if ElasticSearch doesn't (quickly) become responsive."""

    # Never becomes responsive :-)
    ea.es.ping.return_value = False
    ea.es.indices.exists.return_value = False

    clock = mock.MagicMock()
    clock.side_effect = [0.0, 1.0, 2.0, 3.0]
    timeout = datetime.timedelta(seconds=2.5)
    with mock.patch("time.sleep") as sleep:
        with pytest.raises(SystemExit) as exc:
            ea.wait_until_responsive(timeout=timeout, clock=clock)
        assert exc.value.code == 1

    # Ensure we get useful diagnostics.
    output, errors = capsys.readouterr()
    assert 'Could not reach ElasticSearch at "es:14900".' in errors

    # Slept until we passed the deadline.
    sleep.mock_calls == [mock.call(1.0), mock.call(1.0), mock.call(1.0)]


def test_wait_until_responsive_timeout_index_does_not_exist(ea, capsys):
    """Bail out if ElasticSearch doesn't (quickly) become responsive."""

    # Never becomes responsive :-)
    ea.es.ping.return_value = True
    ea.es.indices.exists.return_value = False

    clock = mock.MagicMock()
    clock.side_effect = [0.0, 1.0, 2.0, 3.0]
    timeout = datetime.timedelta(seconds=2.5)
    with mock.patch("time.sleep") as sleep:
        with pytest.raises(SystemExit) as exc:
            ea.wait_until_responsive(timeout=timeout, clock=clock)
        assert exc.value.code == 1

    # Ensure we get useful diagnostics.
    output, errors = capsys.readouterr()
    assert (
        'Writeback alias "wb_a" does not exist, did you run `elastalert-create-index`?'
        in errors
    )

    # Slept until we passed the deadline.
    sleep.mock_calls == [mock.call(1.0), mock.call(1.0), mock.call(1.0)]


def test_stop(ea):
    """ The purpose of this test is to make sure that calling ElastAlerter.stop() will break it
    out of a ElastAlerter.start() loop. This method exists to provide a mechanism for running
    ElastAlert with threads and thus must be tested with threads. mock_loop verifies the loop
    is running and will call stop after several iterations. """

    # Exit the thread on the fourth iteration
    def mock_loop():
        for i in range(3):
            assert ea.running
            yield
        ea.stop()

    with mock.patch.object(ea, "sleep_for", return_value=None):
        with mock.patch.object(ea, "sleep_for") as mock_run:
            mock_run.side_effect = mock_loop()
            start_thread = threading.Thread(target=ea.start)
            # Set as daemon to prevent a failed test from blocking exit
            start_thread.daemon = True
            start_thread.start()

            # Give it a few seconds to run the loop
            start_thread.join(5)

            assert not ea.running
            assert not start_thread.is_alive()
            assert mock_run.call_count == 4


def test_notify_email(ea):
    mock_smtp = mock.Mock()
    ea.rules["testrule"]["notify_email"] = ["foo@foo.foo", "bar@bar.bar"]
    with mock.patch("elastalert.elastalert.SMTP") as mock_smtp_f:
        mock_smtp_f.return_value = mock_smtp

        # Notify_email from rules, array
        ea.send_notification_email("omg", rule=ea.rules["testrule"])
        assert set(mock_smtp.sendmail.call_args_list[0][0][1]) == set(
            ea.rules["testrule"]["notify_email"]
        )

        # With ea.notify_email
        config._cfg.__dict__["mail_settings"] = config.MailSettings(
            notify_email=["baz@baz.baz"]
        )
        ea.send_notification_email("omg", rule=ea.rules["testrule"])
        assert set(mock_smtp.sendmail.call_args_list[1][0][1]) == set(
            ["baz@baz.baz"] + ea.rules["testrule"]["notify_email"]
        )

        # With ea.notify email but as single string
        ea.rules["testrule"]["notify_email"] = "foo@foo.foo"
        ea.send_notification_email("omg", rule=ea.rules["testrule"])
        assert set(mock_smtp.sendmail.call_args_list[2][0][1]) == {
            "baz@baz.baz",
            "foo@foo.foo",
        }

        # None from rule
        ea.rules["testrule"].pop("notify_email")
        ea.send_notification_email("omg", rule=ea.rules["testrule"])
        assert set(mock_smtp.sendmail.call_args_list[3][0][1]) == {"baz@baz.baz"}


def test_uncaught_exceptions(ea, monkeypatch):
    e = Exception("Errors yo!")

    # With disabling set to false
    ea.disable_rules_on_error = False
    config._cfg.__dict__["disable_rules_on_error"] = False
    ea.handle_uncaught_exception(e, ea.rules["testrule"])
    assert len(ea.rules) == 1
    assert len(ea.disabled_rules) == 0

    # With disabling set to true
    config._cfg.__dict__["disable_rules_on_error"] = True
    ea.disable_rules_on_error = True
    ea.handle_uncaught_exception(e, ea.rules["testrule"])
    assert len(ea.rules) == 0
    assert len(ea.disabled_rules) == 1

    # Changing the file should re-enable it
    ea.rule_hashes = {"testrule": "abc"}
    new_hashes = {"testrule": "def"}
    with mock.patch.object(ea.rules_loader, "get_hashes") as mock_hashes:
        with mock.patch.object(ea.rules_loader, "load_rule") as mock_load:
            mock_load.side_effect = [ea.disabled_rules["testrule"]]
            mock_hashes.return_value = new_hashes
            ea.handle_config_change()
    assert len(ea.rules) == 1
    assert len(ea.disabled_rules) == 0

    # Notify email is sent
    config._cfg.__dict__["mail_settings"] = config.MailSettings(
        notify_email=["qlo@example.com"]
    )
    with mock.patch.object(ea, "send_notification_email") as mock_email:
        ea.handle_uncaught_exception(e, ea.rules["testrule"])
    assert mock_email.call_args_list[0][1] == {
        "exception": e,
        "rule": ea.disabled_rules["testrule"],
    }


def test_get_top_counts_handles_no_hits_returned(ea):
    ea.get_hits_terms.return_value = None

    rule = ea.rules["testrule"]
    starttime = datetime.datetime.now() - datetime.timedelta(minutes=10)
    endtime = datetime.datetime.now()
    keys = ["foo"]

    all_counts = ea.get_top_counts(rule, starttime, endtime, keys)
    assert all_counts == {"top_events_foo": {}}


def test_remove_old_events(ea):
    now = ts_now()
    minute = datetime.timedelta(minutes=1)
    ea.rules["testrule"]["processed_hits"] = {
        "foo": now - minute,
        "bar": now - minute * 5,
        "baz": now - minute * 15,
    }
    ea.rules["testrule"]["buffer_time"] = datetime.timedelta(minutes=10)

    # With a query delay, only events older than 20 minutes will be removed (none)
    ea.rules["testrule"]["query_delay"] = datetime.timedelta(minutes=10)
    ea.remove_old_events(ea.rules["testrule"])
    assert len(ea.rules["testrule"]["processed_hits"]) == 3

    # With no query delay, the 15 minute old event will be removed
    ea.rules["testrule"].pop("query_delay")
    ea.remove_old_events(ea.rules["testrule"])
    assert len(ea.rules["testrule"]["processed_hits"]) == 2
    assert "baz" not in ea.rules["testrule"]["processed_hits"]


def test_query_with_whitelist_filter_es(ea):
    ea.rules["testrule"]["_source_enabled"] = False
    ea.rules["testrule"]["five"] = False
    ea.rules["testrule"]["filter"] = [{"query_string": {"query": "baz"}}]
    ea.rules["testrule"]["compare_key"] = "username"
    ea.rules["testrule"]["whitelist"] = ["xudan1", "xudan12", "aa1", "bb1"]
    new_rule = copy.copy(ea.rules["testrule"])
    ea.init_rule(new_rule, True)
    assert (
        'NOT username:"xudan1" AND NOT username:"xudan12" AND NOT username:"aa1"'
        in new_rule["filter"][-1]["query_string"]["query"]
    )


def test_query_with_blacklist_filter_es(ea):
    ea.rules["testrule"]["_source_enabled"] = False
    ea.rules["testrule"]["filter"] = [{"query_string": {"query": "baz"}}]
    ea.rules["testrule"]["compare_key"] = "username"
    ea.rules["testrule"]["blacklist"] = ["xudan1", "xudan12", "aa1", "bb1"]
    new_rule = copy.copy(ea.rules["testrule"])
    ea.init_rule(new_rule, True)
    assert (
        'username:"xudan1" OR username:"xudan12" OR username:"aa1"'
        in new_rule["filter"][-1]["query_string"]["query"]
    )
