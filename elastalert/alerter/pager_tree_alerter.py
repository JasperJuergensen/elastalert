import json
import logging
import uuid

import requests
from requests import RequestException

from elastalert.alerter import Alerter
from elastalert.exceptions import EAException
from elastalert.utils.time import DateTimeEncoder

log = logging.getLogger(__name__)


class PagerTreeAlerter(Alerter):
    """ Creates a PagerTree Incident for each alert """
    required_options = frozenset(['pagertree_integration_url'])

    def __init__(self, rule):
        super(PagerTreeAlerter, self).__init__(rule)
        self.url = self.rule['pagertree_integration_url']
        self.pagertree_proxy = self.rule.get('pagertree_proxy', None)

    def alert(self, matches):
        # post to pagertree
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.pagertree_proxy} if self.pagertree_proxy else None
        payload = {
            "event_type": "create",
            "Id": str(uuid.uuid4()),
            "Title": self.create_title(matches),
            "Description": self.create_alert_body(matches)
        }

        try:
            response = requests.post(self.url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to PagerTree: %s" % e)
        log.info("Trigger sent to PagerTree")

    def get_info(self):
        return {'type': 'pagertree',
                'pagertree_integration_url': self.url}
