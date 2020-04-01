import json
import logging

import requests
from elastalert.alerter import Alerter
from elastalert.alerter.match_string import BasicMatchString
from elastalert.exceptions import EAException
from elastalert.utils.time import DateTimeEncoder
from requests import RequestException

log = logging.getLogger(__name__)


class ServiceNowAlerter(Alerter):
    """ Creates a ServiceNow alert """

    required_options = frozenset(
        [
            "username",
            "password",
            "servicenow_rest_url",
            "short_description",
            "comments",
            "assignment_group",
            "category",
            "subcategory",
            "cmdb_ci",
            "caller_id",
        ]
    )

    def __init__(self, rule):
        super(ServiceNowAlerter, self).__init__(rule)
        self.servicenow_rest_url = self.rule["servicenow_rest_url"]
        self.servicenow_proxy = self.rule.get("servicenow_proxy", None)

    def alert(self, matches):
        for match in matches:
            # Parse everything into description.
            description = str(BasicMatchString(self.rule, match))

        # Set proper headers
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json;charset=utf-8",
        }
        proxies = {"https": self.servicenow_proxy} if self.servicenow_proxy else None
        payload = {
            "description": description,
            "short_description": self.rule["short_description"],
            "comments": self.rule["comments"],
            "assignment_group": self.rule["assignment_group"],
            "category": self.rule["category"],
            "subcategory": self.rule["subcategory"],
            "cmdb_ci": self.rule["cmdb_ci"],
            "caller_id": self.rule["caller_id"],
        }
        try:
            response = requests.post(
                self.servicenow_rest_url,
                auth=(self.rule["username"], self.rule["password"]),
                headers=headers,
                data=json.dumps(payload, cls=DateTimeEncoder),
                proxies=proxies,
            )
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to ServiceNow: %s" % e)
        log.info("Alert sent to ServiceNow")

    def get_info(self):
        return {
            "type": "ServiceNow",
            "self.servicenow_rest_url": self.servicenow_rest_url,
        }
