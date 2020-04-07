import copy
import datetime
import logging
import os

import mock
import pytest

import elastalert.alerter
import elastalert.ruletypes
from elastalert import config
from elastalert.loaders import FileRulesLoader, loader_mapping
from elastalert.utils.util import EAException

test_config = {
    "rules_folder": "test_folder",
    "run_every": {"minutes": 10},
    "buffer_time": {"minutes": 10},
    "es_host": "elasticsearch.test",
    "es_port": 12345,
    "writeback_index": "test_index",
    "writeback_alias": "test_alias",
}

test_rule = {
    "es_host": "test_host",
    "es_port": 12345,
    "name": "testrule",
    "type": "spike",
    "spike_height": 2,
    "spike_type": "up",
    "timeframe": {"minutes": 10},
    "index": "test_index",
    "query_key": "testkey",
    "compare_key": "comparekey",
    "filter": [{"term": {"key": "value"}}],
    "alert": "email",
    "use_count_query": True,
    "doc_type": "blsh",
    "email": "test@test.test",
    "aggregation": {"hours": 2},
    "include": ["comparekey", "@timestamp"],
}

test_args = mock.Mock()
test_args.config = "test_config"
test_args.rule = None
test_args.debug = False
test_args.es_debug_trace = None


#TODO evaluate if should be removed
@pytest.mark.skip
def test_import_rules():
    rules_loader = FileRulesLoader(test_config)
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy["type"] = "testing.test.RuleType"
    with mock.patch.object(rules_loader, "get_rule_config") as mock_open:
        with mock.patch.object(rules_loader, "get_names") as mock_names:
            mock_names.return_value = ["test_rule"]
            mock_open.return_value = test_rule_copy

            # Test that type is imported
            with mock.patch("builtins.__import__") as mock_import:
                mock_import.return_value = elastalert.ruletypes
                rule_config = rules_loader.get_rule_configs(test_config)
                print(rule_config)
            print(mock_import.call_args_list)
            assert mock_import.call_args_list[0][0][0] == "testing.test"
            assert mock_import.call_args_list[0][0][3] == ["RuleType"]

            # Test that alerts are imported
            test_rule_copy = copy.deepcopy(test_rule)
            mock_open.return_value = test_rule_copy
            test_rule_copy["alert"] = "testing2.test2.TestAlerter"
            with mock.patch("builtins.__import__") as mock_import:
                mock_import.return_value = elastalert.alerter.test_alerter
                rules_loader.get_rule_configs(test_config)
            assert mock_import.call_args_list[0][0][0] == "testing2.test2"
            assert mock_import.call_args_list[0][0][3] == ["TestAlerter"]


def setup_test_config():

    config_obj = config.load_config(["--config", "test_config"])
    config.config = config_obj
    return config_obj


def get_test_rule(config_obj):

    rules_loader_class = loader_mapping.get(config_obj['rules_loader'])
    rules_loader = rules_loader_class(config_obj)
    config_obj["rules"] = rules_loader.load(config_obj)
    rules = config_obj["rules"]
    if len(rules) == 0:
        return None
    return config_obj["rules"]['testrule']


def configure_load_rule_and_validate(test_config, test_rule, validation):

    with mock.patch("elastalert.config.yaml_loader") as mock_conf_open:
        mock_conf_open.return_value = test_config
        with mock.patch(
            "elastalert.loaders.file_rules_loader.yaml_loader"
        ) as mock_rule_open:
            mock_rule_open.return_value = test_rule

            with mock.patch("os.walk") as mock_ls:
                mock_ls.return_value = [("", [], ["testrule.yaml"])]
                conf_obj = setup_test_config()
                rule_obj = get_test_rule(conf_obj)
                validation(rule_obj)


def test_import_import():
    rules_loader = FileRulesLoader(test_config)
    import_rule = copy.deepcopy(test_rule)
    del import_rule["es_host"]
    del import_rule["es_port"]
    import_rule["import"] = "importme.ymlt"
    with mock.patch.object(rules_loader, "get_rule_config") as mock_open:
        with mock.patch.object(rules_loader, "get_names") as mock_names:
            mock_names.return_value = ["blah.yaml"]
            import_me = {
                "es_host": "imported_host",
                "es_port": 12349,
                "email": "ignored@email",  # overwritten by the email in import_rule
            }

            mock_open.side_effect = [import_rule, import_me]
            rules = rules_loader.get_rule_configs(test_config)
            assert mock_open.call_args_list[0][0] == ("blah.yaml",)
            assert mock_open.call_args_list[1][0] == ("importme.ymlt",)
            assert len(mock_open.call_args_list) == 2
            assert rules["blah.yaml"]["es_port"] == 12349
            assert rules["blah.yaml"]["es_host"] == "imported_host"
            assert rules["blah.yaml"]["email"] == "test@test.test"
            assert rules["blah.yaml"]["filter"] == import_rule["filter"]

            # check global import_rule dependency
            assert rules_loader.import_rules == {"blah.yaml": ["importme.ymlt"]}


def test_import_absolute_import():
    rules_loader = FileRulesLoader(test_config)
    import_rule = copy.deepcopy(test_rule)
    del import_rule["es_host"]
    del import_rule["es_port"]
    import_rule["import"] = "/importme.ymlt"
    with mock.patch.object(rules_loader, "get_rule_config") as mock_open:
        with mock.patch.object(rules_loader, "get_names") as mock_names:
            mock_names.return_value = ["blah.yaml"]
            import_me = {
                "es_host": "imported_host",
                "es_port": 12349,
                "email": "ignored@email",  # overwritten by the email in import_rule
            }

            mock_open.side_effect = [import_rule, import_me]
            rules = rules_loader.get_rule_configs(test_config)
            assert mock_open.call_args_list[0][0] == ("blah.yaml",)
            assert mock_open.call_args_list[1][0] == ("/importme.ymlt",)
            assert len(mock_open.call_args_list) == 2
            assert rules["blah.yaml"]["es_port"] == 12349
            assert rules["blah.yaml"]["es_host"] == "imported_host"
            assert rules["blah.yaml"]["email"] == "test@test.test"
            assert rules["blah.yaml"]["filter"] == import_rule["filter"]


def test_import_filter():
    # Check that if a filter is specified the rules are merged:

    rules_loader = FileRulesLoader(test_config)
    import_rule = copy.deepcopy(test_rule)
    del import_rule["es_host"]
    del import_rule["es_port"]
    import_rule["import"] = "importme.ymlt"
    with mock.patch.object(rules_loader, "get_rule_config") as mock_open:
        with mock.patch.object(rules_loader, "get_names") as mock_names:
            mock_names.return_value = ["test_rule"]
            import_me = {
                "es_host": "imported_host",
                "es_port": 12349,
                "filter": [{"term": {"ratchet": "clank"}}],
            }

            mock_open.side_effect = [import_rule, import_me]
            rules = rules_loader.get_rule_configs(test_config)
            assert rules["test_rule"]["filter"] == [
                {"term": {"ratchet": "clank"}},
                {"term": {"key": "value"}},
            ]


def test_load_inline_alert_rule(ea):
    rules_loader = FileRulesLoader(test_config)
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy["alert"] = [
        {"email": {"email": "foo@bar.baz"}},
        {"email": {"email": "baz@foo.bar"}},
    ]
    test_config_copy = copy.deepcopy(test_config)
    with mock.patch.object(rules_loader, "get_rule_config") as mock_open:
        with mock.patch.object(rules_loader, "get_names") as mock_names:
            mock_names.return_value = ["test_rule"]
            mock_open.side_effect = [test_config_copy, test_rule_copy]
            rules_loader.load_modules(test_rule_copy)
            assert isinstance(
                test_rule_copy["alert"][0], elastalert.alerter.EmailAlerter
            )
            assert isinstance(
                test_rule_copy["alert"][1], elastalert.alerter.EmailAlerter
            )
            assert "foo@bar.baz" in test_rule_copy["alert"][0].rule["email"]
            assert "baz@foo.bar" in test_rule_copy["alert"][1].rule["email"]


def test_file_rules_loader_get_names_recursive():
    conf = {"scan_subdirectories": True, "rules_folder": "root"}
    rules_loader = FileRulesLoader(conf)
    walk_paths = (
        ("root", ("folder_a", "folder_b"), ("rule.yaml",)),
        ("root/folder_a", (), ("a.yaml", "ab.yaml")),
        ("root/folder_b", (), ("b.yaml",)),
    )
    with mock.patch("os.walk") as mock_walk:
        mock_walk.return_value = walk_paths
        paths = rules_loader.get_names(conf)

    paths = [p.replace(os.path.sep, "/") for p in paths]

    assert "root/rule.yaml" in paths
    assert "root/folder_a/a.yaml" in paths
    assert "root/folder_a/ab.yaml" in paths
    assert "root/folder_b/b.yaml" in paths
    assert len(paths) == 4


def test_file_rules_loader_get_names():
    # Check for no subdirectory
    conf = {"scan_subdirectories": False, "rules_folder": "root"}
    rules_loader = FileRulesLoader(conf)
    files = ["badfile", "a.yaml", "b.yaml"]

    with mock.patch("os.listdir") as mock_list:
        with mock.patch("os.path.isfile") as mock_path:
            mock_path.return_value = True
            mock_list.return_value = files
            paths = rules_loader.get_names(conf)

    paths = [p.replace(os.path.sep, "/") for p in paths]

    assert "root/a.yaml" in paths
    assert "root/b.yaml" in paths
    assert len(paths) == 2


def test_load_rules():

    test_rule_copy = copy.deepcopy(test_rule)
    test_config_copy = copy.deepcopy(test_config)

    def validation(rule_obj):
        assert isinstance(
            rule_obj["type"], elastalert.ruletypes.RuleType
        )
        assert isinstance(
            rule_obj["alert"][0], elastalert.alerter.Alerter
        )
        assert isinstance(rule_obj["timeframe"], datetime.timedelta)
        assert isinstance(rule_obj["run_every"], datetime.timedelta)
        for included_key in ["comparekey", "testkey", "@timestamp"]:
            assert included_key in rule_obj["include"]

        # Assert include doesn't contain duplicates
        assert rule_obj["include"].count("@timestamp") == 1
        assert rule_obj["include"].count("comparekey") == 1

    configure_load_rule_and_validate(test_config_copy, test_rule_copy, validation)


def test_load_default_host_port():

    test_rule_copy = copy.deepcopy(test_rule)
    test_config_copy = copy.deepcopy(test_config)
    test_rule_copy.pop("es_host")
    test_rule_copy.pop("es_port")

    def validation(rule_obj):
        # Assert include doesn't contain duplicates
        assert rule_obj["es_port"] == 12345
        assert rule_obj["es_host"] == "elasticsearch.test"

    configure_load_rule_and_validate(test_config_copy, test_rule_copy, validation)


def test_load_ssl_env_false():
    test_rule_copy = copy.deepcopy(test_rule)
    test_config_copy = copy.deepcopy(test_config)
    test_rule_copy.pop("es_host")
    test_rule_copy.pop("es_port")

    def validation(rule_obj):
        # Assert include doesn't contain duplicates
        assert rule_obj["use_ssl"] is False

    with mock.patch.dict(os.environ, {"ES_USE_SSL": "false"}):
        configure_load_rule_and_validate(test_config_copy, test_rule_copy, validation)


def test_load_ssl_env_true():
    test_rule_copy = copy.deepcopy(test_rule)
    test_config_copy = copy.deepcopy(test_config)
    test_rule_copy.pop("es_host")
    test_rule_copy.pop("es_port")

    def validation(rule_obj):
        # Assert include doesn't contain duplicates
        assert rule_obj["use_ssl"] is True

    with mock.patch.dict(os.environ, {"ES_USE_SSL": "true"}):
        configure_load_rule_and_validate(test_config_copy, test_rule_copy, validation)


def test_load_url_prefix_env():

    test_rule_copy = copy.deepcopy(test_rule)
    test_config_copy = copy.deepcopy(test_config)
    test_rule_copy.pop("es_host")
    test_rule_copy.pop("es_port")

    def validation(rule_obj):
        # Assert include doesn't contain duplicates
        assert rule_obj["es_url_prefix"] == "es/"

    with mock.patch.dict(os.environ, {"ES_URL_PREFIX": "es/"}):
        configure_load_rule_and_validate(test_config_copy, test_rule_copy, validation)


def test_load_disabled_rules():

    test_rule_copy = copy.deepcopy(test_rule)
    test_config_copy = copy.deepcopy(test_config)
    test_rule_copy["is_enabled"] = False

    def validation(rule_obj):
        # Assert include doesn't contain duplicates
        assert rule_obj is None

    with mock.patch.dict(os.environ, {"ES_URL_PREFIX": "es/"}):
        configure_load_rule_and_validate(test_config_copy, test_rule_copy, validation)


def test_raises_on_missing_config(caplog):
    optional_keys = (
        "aggregation",
        "use_count_query",
        "query_key",
        "compare_key",
        "filter",
        "include",
        "es_host",
        "es_port",
        "name",
    )
    test_rule_copy = copy.deepcopy(test_rule)
    for key in list(test_rule_copy.keys()):
        test_rule_copy = copy.deepcopy(test_rule)
        test_config_copy = copy.deepcopy(test_config)
        test_rule_copy.pop(key)

        # Non required keys
        if key in optional_keys:
            continue

        def validate(rule_obj):
            pass

        with caplog.at_level(logging.ERROR):
            configure_load_rule_and_validate(test_config_copy, test_rule_copy, validate)
            assert "is a required property" in caplog.text


def test_compound_query_key():
    test_config_copy = copy.deepcopy(test_config)
    rules_loader = FileRulesLoader(test_config_copy)
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy.pop("use_count_query")
    test_rule_copy["query_key"] = ["field1", "field2"]
    rules_loader.parse_rule_config("filename.yaml", test_rule_copy, test_config)
    assert "field1" in test_rule_copy["include"]
    assert "field2" in test_rule_copy["include"]
    assert test_rule_copy["query_key"] == "field1,field2"
    assert test_rule_copy["compound_query_key"] == ["field1", "field2"]


def test_query_key_with_single_value():
    test_config_copy = copy.deepcopy(test_config)
    rules_loader = FileRulesLoader(test_config_copy)
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy.pop("use_count_query")
    test_rule_copy["query_key"] = ["field1"]
    rules_loader.parse_rule_config("filename.yaml", test_rule_copy, test_config)
    assert "field1" in test_rule_copy["include"]
    assert test_rule_copy["query_key"] == "field1"
    assert "compound_query_key" not in test_rule_copy


def test_query_key_with_no_values():
    test_config_copy = copy.deepcopy(test_config)
    rules_loader = FileRulesLoader(test_config_copy)
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy.pop("use_count_query")
    test_rule_copy["query_key"] = []
    rules_loader.parse_rule_config("filename.yaml", test_rule_copy, test_config)
    assert "query_key" not in test_rule_copy
    assert "compound_query_key" not in test_rule_copy


def test_name_inference():
    test_config_copy = copy.deepcopy(test_config)
    rules_loader = FileRulesLoader(test_config_copy)
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy.pop("name")
    rules_loader.parse_rule_config("msmerc woz ere.yaml", test_rule_copy, test_config)
    assert test_rule_copy["name"] == "msmerc woz ere.yaml"


def test_raises_on_bad_generate_kibana_filters():
    test_rule["generate_kibana_link"] = True
    bad_filters = [
        [{"not": {"terms": {"blah": "blah"}}}],
        [{"terms": {"blah": "blah"}}],
        [{"query": {"not_querystring": "this:that"}}],
        [{"query": {"wildcard": "this*that"}}],
        [{"blah": "blah"}],
    ]
    good_filters = [
        [{"term": {"field": "value"}}],
        [{"not": {"term": {"this": "that"}}}],
        [{"not": {"query": {"query_string": {"query": "this:that"}}}}],
        [{"query": {"query_string": {"query": "this:that"}}}],
        [{"range": {"blah": {"from": "a", "to": "b"}}}],
        [{"not": {"range": {"blah": {"from": "a", "to": "b"}}}}],
    ]

    def get_new_rule_copy(filter):
        test_rule_copy = copy.deepcopy(test_rule)
        test_rule_copy["filter"] = filter
        test_rule_copy["generate_kibana_link"] = True
        return test_rule_copy

    # Test that all the good filters work, but fail with a bad filter added
    for good in good_filters:

        test_config_copy = copy.deepcopy(test_config)

        rules_loader = FileRulesLoader(test_config_copy)


        rules_loader.parse_rule_config('testrule', get_new_rule_copy(good), test_config_copy)

        for bad in bad_filters:
            with pytest.raises(EAException):
                rules_loader.parse_rule_config('testrule', get_new_rule_copy(good + bad), test_config_copy)


def test_kibana_discover_from_timedelta():
    test_config_copy = copy.deepcopy(test_config)
    rules_loader = FileRulesLoader(test_config_copy)
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy["kibana_discover_from_timedelta"] = {"minutes": 2}
    rules_loader.parse_rule_config("filename.yaml", test_rule_copy, test_config)
    assert isinstance(
        test_rule_copy["kibana_discover_from_timedelta"], datetime.timedelta
    )
    assert test_rule_copy["kibana_discover_from_timedelta"] == datetime.timedelta(
        minutes=2
    )


def test_kibana_discover_to_timedelta():
    test_config_copy = copy.deepcopy(test_config)
    rules_loader = FileRulesLoader(test_config_copy)
    test_rule_copy = copy.deepcopy(test_rule)
    test_rule_copy["kibana_discover_to_timedelta"] = {"minutes": 2}
    rules_loader.parse_rule_config("filename.yaml", test_rule_copy, test_config)
    assert isinstance(
        test_rule_copy["kibana_discover_to_timedelta"], datetime.timedelta
    )
    assert test_rule_copy["kibana_discover_to_timedelta"] == datetime.timedelta(
        minutes=2
    )
