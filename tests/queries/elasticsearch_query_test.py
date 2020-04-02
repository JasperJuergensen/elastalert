from unittest import TestCase

from elastalert.queries.elasticsearch_query import ElasticsearchQuery


class TestElasticsearchQuery(TestCase):
    def test_build_query(self):
        query = ElasticsearchQuery({}, None)
        self.assertEqual(query, {"query": {"bool": {"must": {"filter": []}}}})
