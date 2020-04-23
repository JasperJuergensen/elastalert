from datetime import datetime, timedelta
from math import sqrt
from statistics import StatisticsError, harmonic_mean
from unittest import TestCase

import mock
import pytest
from dateutil.parser import parse as dt
from elastalert.utils.arithmetic import (
    Mapping,
    fractional_part,
    interquartile_range,
    mad,
    mean,
    median,
    percentile,
    stdev,
    variance,
)
from elastalert.utils.util import (
    add_raw_postfix,
    format_index,
    lookup_es_key,
    parse_deadline,
    parse_duration,
    replace_dots_in_field_names,
    resolve_string,
    set_es_key,
    should_scrolling_continue,
)


@pytest.mark.parametrize(
    "spec, expected_delta",
    [
        ("hours=2", timedelta(hours=2)),
        ("minutes=30", timedelta(minutes=30)),
        ("seconds=45", timedelta(seconds=45)),
    ],
)
def test_parse_duration(spec, expected_delta):
    """``unit=num`` specs can be translated into ``timedelta`` instances."""
    assert parse_duration(spec) == expected_delta


@pytest.mark.parametrize(
    "spec, expected_deadline",
    [
        ("hours=2", dt("2017-07-07T12:00:00.000Z")),
        ("minutes=30", dt("2017-07-07T10:30:00.000Z")),
        ("seconds=45", dt("2017-07-07T10:00:45.000Z")),
    ],
)
def test_parse_deadline(spec, expected_deadline):
    """``unit=num`` specs can be translated into ``datetime`` instances."""

    # Note: Can't mock ``utcnow`` directly because ``datetime`` is a built-in.
    class MockDatetime(datetime):
        @staticmethod
        def utcnow():
            return dt("2017-07-07T10:00:00.000Z")

    with mock.patch("datetime.datetime", MockDatetime):
        assert parse_deadline(spec) == expected_deadline


def test_setting_keys(ea):
    expected = 12467267
    record = {
        "Message": "12345",
        "Fields": {"ts": "fail", "severity": "large", "user": "jimmay"},
    }

    # Set the value
    assert set_es_key(record, "Fields.ts", expected)

    # Get the value again
    assert lookup_es_key(record, "Fields.ts") == expected


def test_looking_up_missing_keys(ea):
    record = {
        "Message": "12345",
        "Fields": {"severity": "large", "user": "jimmay", "null": None},
    }

    assert lookup_es_key(record, "Fields.ts") is None

    assert lookup_es_key(record, "Fields.null.foo") is None


def test_looking_up_nested_keys(ea):
    expected = 12467267
    record = {
        "Message": "12345",
        "Fields": {"ts": expected, "severity": "large", "user": "jimmay"},
    }

    assert lookup_es_key(record, "Fields.ts") == expected


def test_looking_up_nested_composite_keys(ea):
    expected = 12467267
    record = {
        "Message": "12345",
        "Fields": {"ts.value": expected, "severity": "large", "user": "jimmay"},
    }

    assert lookup_es_key(record, "Fields.ts.value") == expected


def test_looking_up_arrays(ea):
    record = {
        "flags": [1, 2, 3],
        "objects": [{"foo": "bar"}, {"foo": [{"bar": "baz"}]}, {"foo": {"bar": "baz"}}],
    }
    assert lookup_es_key(record, "flags[0]") == 1
    assert lookup_es_key(record, "flags[1]") == 2
    assert lookup_es_key(record, "objects[0]foo") == "bar"
    assert lookup_es_key(record, "objects[1]foo[0]bar") == "baz"
    assert lookup_es_key(record, "objects[2]foo.bar") == "baz"
    assert lookup_es_key(record, "objects[1]foo[1]bar") is None
    assert lookup_es_key(record, "objects[1]foo[0]baz") is None


def test_add_raw_postfix(ea):
    expected = "foo.raw"
    assert add_raw_postfix("foo", False) == expected
    assert add_raw_postfix("foo.raw", False) == expected
    expected = "foo.keyword"
    assert add_raw_postfix("foo", True) == expected
    assert add_raw_postfix("foo.keyword", True) == expected


def test_replace_dots_in_field_names(ea):
    actual = {"a": {"b.c": "d", "e": {"f": {"g.h": 0}}}, "i.j.k": 1, "l": {"m": 2}}
    expected = {"a": {"b_c": "d", "e": {"f": {"g_h": 0}}}, "i_j_k": 1, "l": {"m": 2}}
    assert replace_dots_in_field_names(actual) == expected
    assert replace_dots_in_field_names({"a": 0, 1: 2}) == {"a": 0, 1: 2}


def test_resolve_string(ea):
    match = {
        "name": "mySystem",
        "temperature": 45,
        "humidity": 80.56,
        "sensors": ["outsideSensor", "insideSensor"],
        "foo": {"bar": "baz"},
    }

    expected_outputs = [
        "mySystem is online <MISSING VALUE>",
        "Sensors ['outsideSensor', 'insideSensor'] in the <MISSING VALUE> have temp 45 and 80.56 humidity",
        "Actuator <MISSING VALUE> in the <MISSING VALUE> has temp <MISSING VALUE>",
        "Something baz",
    ]
    old_style_strings = [
        "%(name)s is online %(noKey)s",
        "Sensors %(sensors)s in the %(noPlace)s have temp %(temperature)s and %(humidity)s humidity",
        "Actuator %(noKey)s in the %(noPlace)s has temp %(noKey)s",
        "Something %(foo.bar)s",
    ]

    assert resolve_string(old_style_strings[0], match) == expected_outputs[0]
    assert resolve_string(old_style_strings[1], match) == expected_outputs[1]
    assert resolve_string(old_style_strings[2], match) == expected_outputs[2]
    assert resolve_string(old_style_strings[3], match) == expected_outputs[3]

    new_style_strings = [
        "{name} is online {noKey}",
        "Sensors {sensors} in the {noPlace} have temp {temperature} and {humidity} humidity",
        "Actuator {noKey} in the {noPlace} has temp {noKey}",
        "Something {foo[bar]}",
    ]

    assert resolve_string(new_style_strings[0], match) == expected_outputs[0]
    assert resolve_string(new_style_strings[1], match) == expected_outputs[1]
    assert resolve_string(new_style_strings[2], match) == expected_outputs[2]
    assert resolve_string(new_style_strings[3], match) == expected_outputs[3]


def test_format_index():
    pattern = "logstash-%Y.%m.%d"
    pattern2 = "logstash-%Y.%W"
    date = dt("2018-06-25T12:00:00Z")
    date2 = dt("2018-06-26T12:00:00Z")
    assert sorted(format_index(pattern, date, date).split(",")) == [
        "logstash-2018.06.25"
    ]
    assert sorted(format_index(pattern, date, date2).split(",")) == [
        "logstash-2018.06.25",
        "logstash-2018.06.26",
    ]
    assert sorted(format_index(pattern, date, date2, True).split(",")) == [
        "logstash-2018.06.24",
        "logstash-2018.06.25",
        "logstash-2018.06.26",
    ]
    assert sorted(format_index(pattern2, date, date2, True).split(",")) == [
        "logstash-2018.25",
        "logstash-2018.26",
    ]


def test_should_scrolling_continue():
    rule_no_max_scrolling = {"max_scrolling_count": 0, "scrolling_cycle": 1}
    rule_reached_max_scrolling = {"max_scrolling_count": 2, "scrolling_cycle": 2}
    rule_before_first_run = {"max_scrolling_count": 0, "scrolling_cycle": 0}
    rule_before_max_scrolling = {"max_scrolling_count": 2, "scrolling_cycle": 1}
    rule_over_max_scrolling = {"max_scrolling_count": 2, "scrolling_cycle": 3}

    assert should_scrolling_continue(rule_no_max_scrolling) is True
    assert should_scrolling_continue(rule_reached_max_scrolling) is False
    assert should_scrolling_continue(rule_before_first_run) is True
    assert should_scrolling_continue(rule_before_max_scrolling) is True
    assert should_scrolling_continue(rule_over_max_scrolling) is False


def test_fractional_part():
    assert fractional_part(1) == 0
    assert fractional_part(3.8) == 0.8
    assert fractional_part(100.1234) == 0.1234


def test_percentile():
    assert percentile([1], 0.25) == 1
    assert percentile([1], 0.25, (0, 0, 0, 1)) == 1
    assert percentile([1, 1, 3, 5], 0.3, (0, 0, 0, 1)) == 1
    assert percentile([1, 1, 3, 5], 0.3, (1 / 2, 0, 0, 0)) == 1
    assert percentile([1, 1, 3, 5], 0.3, (1 / 2, 0, 0, 1)) == 1
    assert percentile([1, 1, 3, 5], 0.7, (0, 0, 0, 1)) == 2.6
    assert percentile([1, 1, 3, 5], 0.7, (1 / 2, 0, 0, 0)) == 3
    assert percentile([1, 1, 3, 5], 0.7, (1 / 2, 0, 0, 1)) == 3.6
    assert percentile([1, 1, 3, 5], 0.99, (0, 0, 0, 1)) == 4.92
    with pytest.raises(StatisticsError):
        percentile([])
    with pytest.raises(StatisticsError):
        percentile([1, 2, 3, 4], 1.1)
    with pytest.raises(StatisticsError):
        percentile([1, 2, 3, 4], -0.01)


def test_mad():
    assert mad([1, 2, 3, 4]) == 1
    assert mad([100]) == 0
    assert mad([0, 100]) == 50
    with pytest.raises(StatisticsError):
        mad([])


def test_interquartile_range():
    assert interquartile_range([1]) == 0
    assert interquartile_range([1], (0, 0, 0, 1)) == 0
    assert interquartile_range([1, 1, 3, 5, 4]) == 3
    assert interquartile_range([1, 1, 3, 5, 4], (0, 0, 0, 1)) == 11 / 4
    assert interquartile_range([1, 1, 3, 5, 4], (1 / 2, 0, 0, 1)) == 13 / 4
    assert interquartile_range([1, 1, 3, 5, 4], (1 / 2, 0, 0, 0)) == 3
    with pytest.raises(StatisticsError):
        interquartile_range([])


def test_arithmetic_mapping():
    assert Mapping.get("stdev") == stdev
    assert Mapping.get("not_found", "default") == "default"
    assert Mapping.get("statistics.harmonic_mean") == harmonic_mean
