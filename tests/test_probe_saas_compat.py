from network_guardian.agent.probe import _fleet_endpoint, _fleet_headers


def test_legacy_fleet_endpoint_and_signature_header():
    payload = b'{"agent_id":"NG-123"}'
    endpoint = _fleet_endpoint("http://base:8080", "report", "legacyfleetkey123")
    headers = _fleet_headers(payload, "legacyfleetkey123", "NG-123")

    assert endpoint == "http://base:8080/api/fleet/report"
    assert "X-Agent-Signature" in headers
    assert "X-API-Key" not in headers


def test_saas_fleet_endpoint_and_api_key_header():
    payload = b'{"agent_id":"NG-123"}'
    api_key = "ng_abcd1234.efgh5678"
    endpoint = _fleet_endpoint("http://cloud:8080", "register", api_key)
    headers = _fleet_headers(payload, api_key, "NG-123")

    assert endpoint == "http://cloud:8080/api/v1/fleet/register"
    assert headers["X-API-Key"] == api_key
    assert "X-Agent-Signature" not in headers
