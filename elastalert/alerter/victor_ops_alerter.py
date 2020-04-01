import json
import logging

import requests
from requests import RequestException

from elastalert.alerter import Alerter
from elastalert.exceptions import EAException
from elastalert.utils.time import DateTimeEncoder

log = logging.getLogger(__name__)


class VictorOpsAlerter(Alerter):
    """ Creates a VictorOps Incident for each alert """
    required_options = frozenset(['victorops_api_key', 'victorops_routing_key', 'victorops_message_type'])

    def __init__(self, rule):
        super(VictorOpsAlerter, self).__init__(rule)
        self.victorops_api_key = self.rule['victorops_api_key']
        self.victorops_routing_key = self.rule['victorops_routing_key']
        self.victorops_message_type = self.rule['victorops_message_type']
        self.victorops_entity_id = self.rule.get('victorops_entity_id', None)
        self.victorops_entity_display_name = self.rule.get('victorops_entity_display_name', 'no entity display name')
        self.url = 'https://alert.victorops.com/integrations/generic/20131114/alert/%s/%s' % (
            self.victorops_api_key, self.victorops_routing_key)
        self.victorops_proxy = self.rule.get('victorops_proxy', None)

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # post to victorops
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.victorops_proxy} if self.victorops_proxy else None
        payload = {
            "message_type": self.victorops_message_type,
            "entity_display_name": self.victorops_entity_display_name,
            "monitoring_tool": "ElastAlert",
            "state_message": body
        }
        if self.victorops_entity_id:
            payload["entity_id"] = self.victorops_entity_id

        try:
            response = requests.post(self.url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to VictorOps: %s" % e)
        log.info("Trigger sent to VictorOps")

    def get_info(self):
        return {'type': 'victorops',
                'victorops_routing_key': self.victorops_routing_key}
