import httpx
import pytest
from datetime import datetime, timezone


def test_enrichment_preserves_assessments_and_version_conditions():
    from app.infrastructure.nvd import NvdClient
    data = {"id": "CVE-2021-44228", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "RCE"}], "metrics": {
        "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}}],
        "cvssMetricV40": [{"source": "vendor@example.org", "type": "Secondary", "cvssData": {"version": "4.0", "baseScore": 9.3, "baseSeverity": "CRITICAL", "vectorString": "CVSS:4.0/AV:N"}}]},
        "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.15.0"}, {"vulnerable": False, "criteria": "cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*"}]}]}]}
    captured = []
    def respond(request):
        captured.append(request)
        return httpx.Response(200, json={"vulnerabilities": [{"cve": data}]})
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = NvdClient(client, pause=0).fetch(["CVE-2021-44228", "CVE-2020-1234"])
    record = result["CVE-2021-44228"]
    assert len(record["assessments"]) == 2
    assert record["primary"]["version"] == "4.0"
    assert record["configurations"] == data["configurations"]
    assert "CVE-2020-1234" not in result
    assert captured[0].url.params["cveIds"] == "CVE-2021-44228,CVE-2020-1234"


def test_unassessed_cve_is_not_zero_and_requests_are_batched():
    from app.infrastructure.nvd import NvdClient
    calls = []
    def respond(request):
        calls.append(request)
        ids = request.url.params["cveIds"].split(",")
        return httpx.Response(200, json={"vulnerabilities": [{"cve": {"id": value}} for value in ids]})
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = NvdClient(client, api_key="test", pause=0).fetch([f"CVE-2020-{n:04d}" for n in range(101)])
    assert len(calls) == 2
    assert result["CVE-2020-0000"]["primary"] is None
    assert calls[0].headers["apiKey"] == "test"


@pytest.mark.integration
def test_enrichment_persists_success_and_marks_missing_for_retry(repository, vulnerability):
    from app.application.enrich import Enrich
    repository.save(vulnerability, datetime.now(timezone.utc), baseline=True)
    class Source:
        def fetch(self, ids):
            assert ids == ["CVE-2021-44228"]
            return {ids[0]: {"primary": {"version": "3.1", "score": 10, "severity": "CRITICAL"}}}
    result = Enrich(Source(), repository).run()
    assert result == {"enriched": 1, "missing": 0}
    record = repository.get("CVE-2021-44228")
    assert record["nvd_status"] == "ready"
    assert record["nvd"]["primary"]["score"] == 10
    class Missing:
        def fetch(self, ids):
            return {}
    assert Enrich(Missing(), repository).run()["missing"] == 1
    assert repository.get("CVE-2021-44228")["nvd"]["primary"]["score"] == 10


@pytest.mark.integration
def test_enrichment_failure_preserves_cisa_and_old_nvd(repository, vulnerability):
    from app.application.enrich import Enrich
    repository.save(vulnerability, datetime.now(timezone.utc), baseline=True)
    class Failing:
        def fetch(self, ids):
            raise httpx.ConnectError("offline")
    with pytest.raises(httpx.ConnectError):
        Enrich(Failing(), repository).run()
    assert repository.get("CVE-2021-44228")["nvd_status"] == "pending"
