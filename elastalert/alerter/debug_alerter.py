import logging

from elastalert.alerter import Alerter
from elastalert.alerter.match_string import BasicMatchString
from elastalert.utils.util import lookup_es_key

log = logging.getLogger(__name__)


class DebugAlerter(Alerter):
    """ The debug alerter uses a Python logger (by default, alerting to terminal). """

    def alert(self, matches):
        qk = self.rule.get('query_key', None)
        for match in matches:
            if qk in match:
                log.info(
                    'Alert for %s, %s at %s:' % (self.rule['name'], match[qk], lookup_es_key(match, self.rule['timestamp_field'])))
            else:
                log.info('Alert for %s at %s:' % (self.rule['name'], lookup_es_key(match, self.rule['timestamp_field'])))
            log.info(str(BasicMatchString(self.rule, match)))

    def get_info(self):
        return {'type': 'debug'}
