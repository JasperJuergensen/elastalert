import json
import logging
import warnings
from html.parser import HTMLParser

import requests
from requests import RequestException

from elastalert.alerter import Alerter
from elastalert.exceptions import EAException
from elastalert.utils.time import DateTimeEncoder

log = logging.getLogger(__name__)


class StrideHTMLParser(HTMLParser):
    """Parse html into stride's fabric structure"""

    def __init__(self):
        """
        Define a couple markup place holders.
        """
        self.content = []
        self.mark = None
        HTMLParser.__init__(self)

    def handle_starttag(self, tag, attrs):
        """Identify and verify starting tag is fabric compatible."""
        if tag == 'b' or tag == 'strong':
            self.mark = dict(type='strong')
        if tag == 'u':
            self.mark = dict(type='underline')
        if tag == 'a':
            self.mark = dict(type='link', attrs=dict(attrs))

    def handle_endtag(self, tag):
        """Clear mark on endtag."""
        self.mark = None

    def handle_data(self, data):
        """Construct data node for our data."""
        node = dict(type='text', text=data)
        if self.mark:
            node['marks'] = [self.mark]
        self.content.append(node)


class StrideAlerter(Alerter):
    """ Creates a Stride conversation message for each alert """

    required_options = frozenset(
        ['stride_access_token', 'stride_cloud_id', 'stride_conversation_id'])

    def __init__(self, rule):
        super(StrideAlerter, self).__init__(rule)

        self.stride_access_token = self.rule['stride_access_token']
        self.stride_cloud_id = self.rule['stride_cloud_id']
        self.stride_conversation_id = self.rule['stride_conversation_id']
        self.stride_ignore_ssl_errors = self.rule.get('stride_ignore_ssl_errors', False)
        self.stride_proxy = self.rule.get('stride_proxy', None)
        self.url = 'https://api.atlassian.com/site/%s/conversation/%s/message' % (
            self.stride_cloud_id, self.stride_conversation_id)

    def alert(self, matches):
        body = self.create_alert_body(matches).strip()

        # parse body with StrideHTMLParser
        parser = StrideHTMLParser()
        parser.feed(body)

        # Post to Stride
        headers = {
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(self.stride_access_token)
        }

        # set https proxy, if it was provided
        proxies = {'https': self.stride_proxy} if self.stride_proxy else None

        # build stride json payload
        # https://developer.atlassian.com/cloud/stride/apis/document/structure/
        payload = {'body': {'version': 1, 'type': "doc", 'content': [
            {'type': "panel", 'attrs': {'panelType': "warning"}, 'content': [
                {'type': 'paragraph', 'content': parser.content}
            ]}
        ]}}

        try:
            if self.stride_ignore_ssl_errors:
                requests.packages.urllib3.disable_warnings()
            response = requests.post(
                self.url, data=json.dumps(payload, cls=DateTimeEncoder),
                headers=headers, verify=not self.stride_ignore_ssl_errors,
                proxies=proxies)
            warnings.resetwarnings()
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Stride: %s" % e)
        log.info(
            "Alert sent to Stride conversation %s" % self.stride_conversation_id)

    def get_info(self):
        return {'type': 'stride',
                'stride_cloud_id': self.stride_cloud_id,
                'stride_converstation_id': self.stride_converstation_id}
