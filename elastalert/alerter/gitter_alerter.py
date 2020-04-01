import json
import logging

import requests
from elastalert.alerter import Alerter
from elastalert.exceptions import EAException
from elastalert.utils.time import DateTimeEncoder
from requests import RequestException

log = logging.getLogger(__name__)


class GitterAlerter(Alerter):
    """ Creates a Gitter activity message for each alert """

    required_options = frozenset(["gitter_webhook_url"])

    def __init__(self, rule):
        super(GitterAlerter, self).__init__(rule)
        self.gitter_webhook_url = self.rule["gitter_webhook_url"]
        self.gitter_proxy = self.rule.get("gitter_proxy", None)
        self.gitter_msg_level = self.rule.get("gitter_msg_level", "error")

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # post to Gitter
        headers = {"content-type": "application/json"}
        # set https proxy, if it was provided
        proxies = {"https": self.gitter_proxy} if self.gitter_proxy else None
        payload = {"message": body, "level": self.gitter_msg_level}

        try:
            response = requests.post(
                self.gitter_webhook_url,
                json.dumps(payload, cls=DateTimeEncoder),
                headers=headers,
                proxies=proxies,
            )
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Gitter: %s" % e)
        log.info("Alert sent to Gitter")

    def get_info(self):
        return {"type": "gitter", "gitter_webhook_url": self.gitter_webhook_url}
