import hashlib
import unittest

import mock
import pytest
from elastalert.exceptions import EAException
from elastalert.loaders import FileRulesLoader


class FileRulesLoaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.test_config = {}
        self.rules_loader = FileRulesLoader(self.test_config)

    def test_get_rule_configs(self):
        with mock.patch.object(
            self.rules_loader,
            "get_names",
            mock.MagicMock(return_value=["test1.yaml", "test2.yaml"]),
        ):
            with mock.patch.object(
                self.rules_loader,
                "load_rule",
                mock.MagicMock(return_value={"test": "test"}),
            ):
                self.assertEqual(
                    {"test1.yaml": {"test": "test"}, "test2.yaml": {"test": "test"}},
                    self.rules_loader.get_rule_configs(self.test_config),
                )

    def test_get_names(self):
        self.test_config["rules_folder"] = "test"
        with mock.patch(
            "elastalert.loaders.file_rules_loader.os.listdir",
            mock.MagicMock(return_value=["test1.yaml", "test2.yml"]),
        ):
            with mock.patch(
                "elastalert.loaders.file_rules_loader.os.path.isfile",
                mock.MagicMock(return_value=True),
            ):
                self.assertEqual(
                    ["test/test1.yaml", "test/test2.yml"],
                    self.rules_loader.get_names(self.test_config),
                )
        self.test_config["scan_subdirectories"] = True
        with mock.patch(
            "elastalert.loaders.file_rules_loader.os.walk",
            mock.MagicMock(
                return_value=[
                    ("folder1/folder2", "", ["test1.yml"]),
                    ("folder1", "", ["test2.yaml", "test3.yaml"]),
                ]
            ),
        ):
            self.assertEqual(
                [
                    "folder1/folder2/test1.yml",
                    "folder1/test2.yaml",
                    "folder1/test3.yaml",
                ],
                self.rules_loader.get_names(self.test_config),
            )

    def test_get_hashes(self):
        with mock.patch.object(
            self.rules_loader,
            "get_names",
            mock.MagicMock(return_value=["test1", "test2"]),
        ):
            with mock.patch.object(
                self.rules_loader,
                "get_rule_file_hash",
                mock.MagicMock(return_value="test"),
            ):
                self.assertEqual(
                    {"test1": "test", "test2": "test"},
                    self.rules_loader.get_hashes(self.test_config),
                )

    @mock.patch("builtins.open", mock.mock_open(read_data=b"test:\n    hello: world"))
    def test_get_rule_config(self):
        self.assertEqual(
            {"test": {"hello": "world"}}, self.rules_loader.get_rule_config("test")
        )

    @mock.patch("builtins.open", mock.mock_open(read_data=b"test:\nhello world"))
    def test_get_rule_config_invalid_yaml_file(self):
        with pytest.raises(EAException):
            self.rules_loader.get_rule_config("test")

    def test_get_import_rule(self):
        self.assertEqual(
            "/import_file",
            self.rules_loader.get_import_rule({"import": "/import_file"}),
        )
        self.assertEqual(
            "/folder/import_file",
            self.rules_loader.get_import_rule(
                {"import": "import_file", "rule_file": "/folder/rule_file"}
            ),
        )

    @mock.patch("elastalert.loaders.file_rules_loader.os.path.exists")
    @mock.patch("builtins.open", mock.mock_open(read_data=b"test"))
    def test_get_rule_file_hash(self, mock_path_exists):
        mock_path_exists.return_value = True
        self.assertEqual(
            hashlib.sha1(b"test").digest(), self.rules_loader.get_rule_file_hash("test")
        )
        mock_path_exists.return_value = False
        self.assertEqual("", self.rules_loader.get_rule_file_hash("test"))

    @mock.patch(
        "elastalert.loaders.file_rules_loader.os.path.exists",
        mock.MagicMock(return_value=True),
    )
    @mock.patch("builtins.open", mock.mock_open(read_data=b"test"))
    def test_get_rule_file_hash_with_import(self):
        self.rules_loader.import_rules = {"test": ["import_test"]}
        self.assertEqual(
            hashlib.sha1(
                hashlib.sha1(b"test").digest() + hashlib.sha1(b"test").digest()
            ).digest(),
            self.rules_loader.get_rule_file_hash("test"),
        )

    def test_is_yaml(self):
        self.assertTrue(FileRulesLoader.is_yaml("test.yaml"))
        self.assertTrue(FileRulesLoader.is_yaml("test.yml"))
        self.assertFalse(FileRulesLoader.is_yaml("test.xml"))
