import json
import time
import uuid

import requests
from elastalert.alerter import Alerter
from elastalert.exceptions import EAException


class HiveAlerter(Alerter):
    """
    Use matched data to create alerts containing observables in an instance of TheHive
    """

    required_options = frozenset(["hive_connection", "hive_alert_config"])

    def get_aggregation_summary_text(self, matches):
        text = super(HiveAlerter, self).get_aggregation_summary_text(matches)
        if text:
            text = u"```\n{0}```\n".format(text)
        return text

    def create_artifacts(self, match):
        artifacts = []
        context = {"rule": self.rule, "match": match}
        for mapping in self.rule.get("hive_observable_data_mapping", []):
            for observable_type, match_data_key in mapping.items():
                try:
                    artifact = {
                        "tlp": 2,
                        "tags": [],
                        "message": None,
                        "dataType": observable_type,
                        "data": match_data_key.format(**context),
                    }
                    artifacts.append(artifact)
                except KeyError:
                    print(
                        "\nformat string\n{}\nmatch data\n{}".format(
                            match_data_key, context
                        )
                    )

        if self.rule.get("hive_observables_key", "observables") in match:
            for mapping in match[self.rule.get("hive_observables_key", "observables")]:
                for observable_type, observable_data in mapping.items():
                    artifact = {
                        "tlp": 2,
                        "tags": [],
                        "message": None,
                        "dataType": observable_type,
                        "data": observable_data,
                    }
                    artifacts.append(artifact)

        return artifacts

    def create_alert_config(self, match):
        context = {"rule": self.rule, "match": match}
        alert_config = {
            "artifacts": self.create_artifacts(match),
            "sourceRef": str(uuid.uuid4())[0:6],
            "customFields": {},
            "caseTemplate": None,
            "title": "{rule[index]}_{rule[name]}".format(**context),
            "date": int(time.time()) * 1000,
        }

        alert_config.update(self.rule.get("hive_alert_config", {}))

        custom_fields = {}
        for alert_config_field, alert_config_value in alert_config.items():
            if alert_config_field == "customFields":
                n = 0
                for cf_key, cf_value in alert_config_value.items():
                    cf = {
                        "order": n,
                        cf_value["type"]: cf_value["value"].format(**context),
                    }
                    n += 1
                    custom_fields[cf_key] = cf
            elif isinstance(alert_config_value, str):
                if alert_config_field in ["tlp", "severity"]:
                    alert_config[alert_config_field] = int(
                        alert_config_value.format(**context), 10
                    )
                else:
                    alert_config[alert_config_field] = alert_config_value.format(
                        **context
                    )
            elif isinstance(alert_config_value, (list, tuple)):
                formatted_list = []
                for element in alert_config_value:
                    try:
                        formatted_list.append(element.format(**context))
                    except (AttributeError, KeyError, IndexError):
                        formatted_list.append(element)
                alert_config[alert_config_field] = formatted_list
        if custom_fields:
            alert_config["customFields"] = custom_fields

        return alert_config

    def send_to_thehive(self, alert_config):
        connection_details = self.rule["hive_connection"]

        alert_body = json.dumps(alert_config, indent=4, sort_keys=True)
        req = "{}:{}/api/alert".format(
            connection_details["hive_host"], connection_details["hive_port"]
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(
                connection_details.get("hive_api_key", "")
            ),
        }
        proxies = connection_details.get("hive_proxies", {"http": "", "https": ""})
        verify = connection_details.get("hive_verify", False)
        response = requests.post(
            req, headers=headers, data=alert_body, proxies=proxies, verify=verify
        )

        if response.status_code != 201:
            raise EAException(
                "alert not successfully created in TheHive\n{}".format(response.text)
            )

    def alert(self, matches):
        if self.rule.get("hive_alert_config_type", "custom") != "classic":
            for match in matches:
                alert_config = self.create_alert_config(match)
                self.send_to_thehive(alert_config)
        else:
            alert_config = self.create_alert_config(matches[0])
            artifacts = []
            for match in matches:
                artifacts += self.create_artifacts(match)
                if "related_events" in match:
                    for related_event in match["related_events"]:
                        artifacts += self.create_artifacts(related_event)

            alert_config["artifacts"] = artifacts
            alert_config["title"] = self.create_title(matches)
            alert_config["description"] = self.create_alert_body(matches)
            self.send_to_thehive(alert_config)

    def get_info(self):

        return {
            "type": "hivealerter",
            "hive_host": self.rule.get("hive_connection", {}).get("hive_host", ""),
        }
