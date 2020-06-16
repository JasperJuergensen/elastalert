# flake8: noqa
from elastalert.loaders.rules_loader import RulesLoader
from elastalert.loaders.file_rules_loader import FileRulesLoader

# Used to map the names of rule loaders to their classes
loader_mapping = {"file": FileRulesLoader}
