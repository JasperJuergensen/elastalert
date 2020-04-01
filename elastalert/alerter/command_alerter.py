import json
import logging
import subprocess

from elastalert.alerter import Alerter
from elastalert.exceptions import EAException
from elastalert.utils.time import DateTimeEncoder
from elastalert.utils.util import resolve_string

log = logging.getLogger(__name__)


class CommandAlerter(Alerter):
    required_options = set(["command"])

    def __init__(self, *args):
        super(CommandAlerter, self).__init__(*args)

        self.last_command = []

        self.shell = False
        if isinstance(self.rule["command"], str):
            self.shell = True
            if "%" in self.rule["command"]:
                log.warning("Warning! You could be vulnerable to shell injection!")
            self.rule["command"] = [self.rule["command"]]

        self.new_style_string_format = False
        if (
            "new_style_string_format" in self.rule
            and self.rule["new_style_string_format"]
        ):
            self.new_style_string_format = True

    def alert(self, matches):
        # Format the command and arguments
        try:
            command = [
                resolve_string(command_arg, matches[0])
                for command_arg in self.rule["command"]
            ]
            self.last_command = command
        except KeyError as e:
            raise EAException("Error formatting command: %s" % (e))

        # Run command and pipe data
        try:
            subp = subprocess.Popen(command, stdin=subprocess.PIPE, shell=self.shell)

            if self.rule.get("pipe_match_json"):
                match_json = json.dumps(matches, cls=DateTimeEncoder) + "\n"
                stdout, stderr = subp.communicate(input=match_json.encode())
            elif self.rule.get("pipe_alert_text"):
                alert_text = self.create_alert_body(matches)
                stdout, stderr = subp.communicate(input=alert_text.encode())
            if self.rule.get("fail_on_non_zero_exit", False) and subp.wait():
                raise EAException(
                    "Non-zero exit code while running command %s" % (" ".join(command))
                )
        except OSError as e:
            raise EAException(
                "Error while running command %s: %s" % (" ".join(command), e)
            )

    def get_info(self):
        return {"type": "command", "command": " ".join(self.last_command)}
