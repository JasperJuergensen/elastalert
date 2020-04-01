import logging

import requests
from requests import RequestException

from elastalert.alerter import Alerter
from elastalert.exceptions import EAException

log = logging.getLogger(__name__)


class LineNotifyAlerter(Alerter):
    """ Created a Line Notify for each alert """
    required_option = frozenset(["linenotify_access_token"])

    def __init__(self, rule):
        super(LineNotifyAlerter, self).__init__(rule)
        self.linenotify_access_token = self.rule["linenotify_access_token"]

    def alert(self, matches):
        body = self.create_alert_body(matches)
        # post to Line Notify
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer {}".format(self.linenotify_access_token)
        }
        payload = {
            "message": body
        }
        try:
            response = requests.post("https://notify-api.line.me/api/notify", data=payload, headers=headers)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Line Notify: %s" % e)
        log.info("Alert sent to Line Notify")

    def get_info(self):
        return {"type": "linenotify", "linenotify_access_token": self.linenotify_access_token}
