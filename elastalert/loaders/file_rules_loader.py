import hashlib
import os

import yaml
from staticconf.loader import yaml_loader

from elastalert.exceptions import EAException
from elastalert.loaders import RulesLoader


class FileRulesLoader(RulesLoader):

    # Required global (config.yaml) configuration options for the loader
    required_globals = frozenset(['rules_folder'])

    def get_names(self, conf, use_rule=None):
        # Passing a filename directly can bypass rules_folder and .yaml checks
        if use_rule and os.path.isfile(use_rule):
            return [use_rule]
        rule_folder = conf['rules_folder']
        rule_files = []
        if 'scan_subdirectories' in conf and conf['scan_subdirectories']:
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

    def get_hashes(self, conf, use_rule=None):
        rule_files = self.get_names(conf, use_rule)
        rule_mod_times = {}
        for rule_file in rule_files:
            rule_mod_times[rule_file] = self.get_rule_file_hash(rule_file)
        return rule_mod_times

    def get_yaml(self, filename):
        try:
            return yaml_loader(filename)
        except yaml.scanner.ScannerError as e:
            raise EAException('Could not parse file %s: %s' % (filename, e))

    def get_import_rule(self, rule):
        """
        Allow for relative paths to the import rule.
        :param dict rule:
        :return: Path the import rule
        :rtype: str
        """
        if os.path.isabs(rule['import']):
            return rule['import']
        else:
            return os.path.join(os.path.dirname(rule['rule_file']), rule['import'])

    def get_rule_file_hash(self, rule_file):
        rule_file_hash = ''
        if os.path.exists(rule_file):
            with open(rule_file, 'rb') as fh:
                rule_file_hash = hashlib.sha1(fh.read()).digest()
            for import_rule_file in self.import_rules.get(rule_file, []):
                rule_file_hash += self.get_rule_file_hash(import_rule_file)
        return rule_file_hash

    @staticmethod
    def is_yaml(filename):
        return filename.endswith('.yaml') or filename.endswith('.yml')
