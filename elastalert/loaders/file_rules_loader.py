import hashlib
import os
from typing import Dict, List

import staticconf.loader
from elastalert.exceptions import EAException
from elastalert.loaders import RulesLoader
from yaml import scanner


class FileRulesLoader(RulesLoader):

    # Required global (config.yaml) configuration options for the loader
    required_globals = frozenset(["rules_folder"])

    def get_names(self, use_rule: str = None) -> List[str]:
        # Passing a filename directly can bypass rules_folder and .yaml checks
        if use_rule and os.path.isfile(use_rule):
            return [use_rule]
        rule_folder = self.base_config.rules_folder
        rule_files = []
        if self.base_config.scan_subdirectories:
            for root, folders, files in os.walk(rule_folder):
                for filename in files:
                    if use_rule and use_rule != filename:
                        continue
                    if self.is_yaml(filename):
                        rule_files.append(os.path.join(root, filename))
        else:
            for filename in os.listdir(rule_folder):
                fullpath = os.path.join(rule_folder, filename)
                if os.path.isfile(fullpath) and self.is_yaml(filename):
                    rule_files.append(fullpath)
        return rule_files

    def get_hashes(self, use_rule: str = None) -> Dict[str, int]:
        rule_files = self.get_names(use_rule)
        return {
            rule_file: self.get_rule_file_hash(rule_file) for rule_file in rule_files
        }

    def get_rule_config(self, filename: str) -> dict:
        """
        Loads yaml from file

        :param filename: The rule file
        :return: dict with rule config
        """
        try:
            return staticconf.loader.yaml_loader(filename)
        except scanner.ScannerError as e:
            raise EAException("Could not parse file %s: %s" % (filename, e))

    def get_import_rule(self, rule_config: dict) -> str:
        """
        Allow for relative paths to the import rule.
        :param dict rule_config:
        :return: Path the import rule
        :rtype: str
        """
        if os.path.isabs(rule_config["import"]):
            return rule_config["import"]
        else:
            return os.path.join(
                os.path.dirname(rule_config["rule_file"]), rule_config["import"]
            )

    def get_rule_file_hash(self, rule_file: str) -> int:
        """
        Creates a hash over a rule file

        :param rule_file: The rule
        :return: sha1 hash digest
        """
        rule_file_hash = 0
        if os.path.exists(rule_file):
            with open(rule_file, "rb") as fh:
                rule_file_hash = int.from_bytes(hashlib.sha1(fh.read()).digest(), "big")
            for import_rule_file in self.import_rules.get(rule_file, []):
                rule_file_hash = int.from_bytes(
                    hashlib.sha1(
                        (
                            rule_file_hash + self.get_rule_file_hash(import_rule_file)
                        ).to_bytes(22, "big")
                    ).digest(),
                    "big",
                )
        return rule_file_hash

    @staticmethod
    def is_yaml(filename: str) -> bool:
        """
        Checks if a file ends with a yaml extension

        :param filename: The file
        :return bool:
        """
        return filename.endswith(".yaml") or filename.endswith(".yml")
