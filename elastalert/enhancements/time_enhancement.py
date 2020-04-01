from elastalert.enhancements import BaseEnhancement

from elastalert.utils.time import pretty_ts


class TimeEnhancement(BaseEnhancement):
    def process(self, match):
        match['@timestamp'] = pretty_ts(match['@timestamp'])
