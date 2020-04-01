import logging

import boto3
from elastalert.alerter import Alerter

log = logging.getLogger(__name__)


class SnsAlerter(Alerter):
    """ Send alert using AWS SNS service """

    required_options = frozenset(["sns_topic_arn"])

    def __init__(self, *args):
        super(SnsAlerter, self).__init__(*args)
        self.sns_topic_arn = self.rule.get("sns_topic_arn", "")
        self.aws_access_key_id = self.rule.get("aws_access_key_id")
        self.aws_secret_access_key = self.rule.get("aws_secret_access_key")
        self.aws_region = self.rule.get("aws_region", "us-east-1")
        self.profile = self.rule.get("boto_profile", None)  # Deprecated
        self.profile = self.rule.get("aws_profile", None)

    def create_default_title(self, matches):
        subject = "ElastAlert: %s" % (self.rule["name"])
        return subject

    def alert(self, matches):
        body = self.create_alert_body(matches)

        session = boto3.Session(
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            region_name=self.aws_region,
            profile_name=self.profile,
        )
        sns_client = session.client("sns")
        sns_client.publish(
            TopicArn=self.sns_topic_arn,
            Message=body,
            Subject=self.create_title(matches),
        )
        log.info("Sent sns notification to %s" % (self.sns_topic_arn))
