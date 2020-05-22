from elastalert.enhancements import BaseEnhancement
from elastalert.utils.elastic import get_query_key_value


class QueryKeyEnhancement(BaseEnhancement):
    def process(self, match):
        qk = self.rule["query_key"]
        if qk is not None:
            match["query_key"] = qk
            qk_value = get_query_key_value(self.rule, match)
            if qk_value is not None:
                match["query_key_value"] = qk_value
