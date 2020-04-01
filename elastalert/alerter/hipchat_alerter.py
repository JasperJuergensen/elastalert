import json
import logging
import warnings

import requests
from requests import RequestException

from elastalert.alerter import Alerter
from elastalert.exceptions import EAException
from elastalert.utils.time import DateTimeEncoder

log = logging.getLogger(__name__)


class HipChatAlerter(Alerter):
    """ Creates a HipChat room notification for each alert """
    required_options = frozenset(['hipchat_auth_token', 'hipchat_room_id'])

    def __init__(self, rule):
        super(HipChatAlerter, self).__init__(rule)
        self.hipchat_msg_color = self.rule.get('hipchat_msg_color', 'red')
        self.hipchat_message_format = self.rule.get('hipchat_message_format', 'html')
        self.hipchat_auth_token = self.rule['hipchat_auth_token']
        self.hipchat_room_id = self.rule['hipchat_room_id']
        self.hipchat_domain = self.rule.get('hipchat_domain', 'api.hipchat.com')
        self.hipchat_ignore_ssl_errors = self.rule.get('hipchat_ignore_ssl_errors', False)
        self.hipchat_notify = self.rule.get('hipchat_notify', True)
        self.hipchat_from = self.rule.get('hipchat_from', '')
        self.url = 'https://%s/v2/room/%s/notification?auth_token=%s' % (
            self.hipchat_domain, self.hipchat_room_id, self.hipchat_auth_token)
        self.hipchat_proxy = self.rule.get('hipchat_proxy', None)

    def create_alert_body(self, matches):
        body = super(HipChatAlerter, self).create_alert_body(matches)

        # HipChat sends 400 bad request on messages longer than 10000 characters
        if self.hipchat_message_format == 'html':
            # Use appropriate line ending for text/html
            br = '<br/>'
            body = body.replace('\n', br)

            truncated_message = '<br/> ...(truncated)'
            truncate_to = 10000 - len(truncated_message)
        else:
            truncated_message = '..(truncated)'
            truncate_to = 10000 - len(truncated_message)

        if (len(body) > 9999):
            body = body[:truncate_to] + truncated_message

        return body

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # Post to HipChat
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.hipchat_proxy} if self.hipchat_proxy else None
        payload = {
            'color': self.hipchat_msg_color,
            'message': body,
            'message_format': self.hipchat_message_format,
            'notify': self.hipchat_notify,
            'from': self.hipchat_from
        }

        try:
            if self.hipchat_ignore_ssl_errors:
                requests.packages.urllib3.disable_warnings()

            if self.rule.get('hipchat_mentions', []):
                ping_users = self.rule.get('hipchat_mentions', [])
                ping_msg = payload.copy()
                ping_msg['message'] = "ping {}".format(
                    ", ".join("@{}".format(user) for user in ping_users)
                )
                ping_msg['message_format'] = "text"

                response = requests.post(
                    self.url,
                    data=json.dumps(ping_msg, cls=DateTimeEncoder),
                    headers=headers,
                    verify=not self.hipchat_ignore_ssl_errors,
                    proxies=proxies)

            response = requests.post(self.url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers,
                                     verify=not self.hipchat_ignore_ssl_errors,
                                     proxies=proxies)
            warnings.resetwarnings()
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to HipChat: %s" % e)
        log.info("Alert sent to HipChat room %s" % self.hipchat_room_id)

    def get_info(self):
        return {'type': 'hipchat',
                'hipchat_room_id': self.hipchat_room_id}
