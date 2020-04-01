import logging
import sys

from elastalert.alerter import Alerter
from elastalert.exceptions import EAException
from exotel import Exotel
from requests import RequestException

log = logging.getLogger(__name__)


class ExotelAlerter(Alerter):
    required_options = frozenset(
        [
            "exotel_account_sid",
            "exotel_auth_token",
            "exotel_to_number",
            "exotel_from_number",
        ]
    )

    def __init__(self, rule):
        super(ExotelAlerter, self).__init__(rule)
        self.exotel_account_sid = self.rule["exotel_account_sid"]
        self.exotel_auth_token = self.rule["exotel_auth_token"]
        self.exotel_to_number = self.rule["exotel_to_number"]
        self.exotel_from_number = self.rule["exotel_from_number"]
        self.sms_body = self.rule.get("exotel_message_body", "")

    def alert(self, matches):
        client = Exotel(self.exotel_account_sid, self.exotel_auth_token)

        try:
            message_body = self.rule["name"] + self.sms_body
            response = client.sms(
                self.rule["exotel_from_number"],
                self.rule["exotel_to_number"],
                message_body,
            )
            if response != 200:
                raise EAException(
                    "Error posting to Exotel, response code is %s" % response
                )
        except RequestException:
            raise EAException("Error posting to Exotel").with_traceback(
                sys.exc_info()[2]
            )
        log.info("Trigger sent to Exotel")

    def get_info(self):
        return {"type": "exotel", "exotel_account": self.exotel_account_sid}
