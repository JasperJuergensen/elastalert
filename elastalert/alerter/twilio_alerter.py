import logging

from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client as TwilioClient

from elastalert.alerter import Alerter
from elastalert.exceptions import EAException

log = logging.getLogger(__name__)


class TwilioAlerter(Alerter):
    required_options = frozenset(['twilio_account_sid', 'twilio_auth_token', 'twilio_to_number', 'twilio_from_number'])

    def __init__(self, rule):
        super(TwilioAlerter, self).__init__(rule)
        self.twilio_account_sid = self.rule['twilio_account_sid']
        self.twilio_auth_token = self.rule['twilio_auth_token']
        self.twilio_to_number = self.rule['twilio_to_number']
        self.twilio_from_number = self.rule['twilio_from_number']

    def alert(self, matches):
        client = TwilioClient(self.twilio_account_sid, self.twilio_auth_token)

        try:
            client.messages.create(body=self.rule['name'],
                                   to=self.twilio_to_number,
                                   from_=self.twilio_from_number)

        except TwilioRestException as e:
            raise EAException("Error posting to twilio: %s" % e)

        log.info("Trigger sent to Twilio")

    def get_info(self):
        return {'type': 'twilio',
                'twilio_client_name': self.twilio_from_number}
