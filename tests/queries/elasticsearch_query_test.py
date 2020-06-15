from elastalert.queries.elasticsearch_query import ElasticsearchQuery


def test_build_query():
    query = ElasticsearchQuery({}, None, {})
    assert {"query": {"bool": {"filter": []}}, "sort": ["@timestamp"]} == query.query
