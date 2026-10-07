import httpx
import pytest
from pydantic import ValidationError
from app.domain.vulnerability import Vulnerability


def test_vulnerability_identity_and_normalization():
    record = Vulnerability(
        cve_id="CVE-2021-44228",
        vendor=" Apache ",
        product="Log4j",
        title=" Log4Shell ",
        description="Remote execution",
        action="Upgrade",
        date_added="2021-12-10",
        due_date="2021-12-24",
        ransomware="Known",
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    )
    assert record.vendor == "Apache"
    assert record.title == "Log4Shell"
    assert record.product_key == "apache::log4j"
    assert record.snapshot()["cve_id"] == "CVE-2021-44228"


@pytest.mark.parametrize(
    "field,value",
    [("cve_id", "wrong"), ("vendor", ""), ("ransomware", "No"), ("due_date", "2020-01-01")],
)
def test_invalid_source_data_is_rejected(field, value):
    data = dict(
        cve_id="CVE-2021-44228",
        vendor="Apache",
        product="Log4j",
        title="Log4Shell",
        description="RCE",
        action="Upgrade",
        date_added="2021-12-10",
        due_date="2021-12-24",
        ransomware="Known",
        source_url="https://www.cisa.gov/catalog",
    )
    with pytest.raises(ValidationError):
        Vulnerability(**(data | {field: value}))


HTML = """<article class="c-teaser"><div class="c-teaser__meta">Apache | Log4j</div>
<h3 class="c-teaser__title"><a>CVE-2021-44228</a></h3>
<div class="c-teaser__vuln-name">Log4Shell: <span>Remote execution</span></div>
<ul><li>Known To Be Used in Ransomware Campaigns? <strong>Known</strong></li>
<li><span>Date Added:</span> 2021-12-10</li><li><span>Due Date:</span> 2021-12-24</li></ul>
<div class="c-teaser__teaser-action"><span>Action:</span> Upgrade</div>
<a class="c-teaser__cwe">CWE-502</a><div class="c-teaser__notes"><a href="https://example.org/advisory">Advisory</a></div></article>"""


def test_crawler_follows_pagination_and_extracts_labeled_fields():
    from app.infrastructure.cisa import CisaCrawler

    visited = []

    def respond(request):
        visited.append(str(request.url))
        body = HTML + ('<a rel="next" href="?page=1">Next</a>' if not request.url.query else "")
        return httpx.Response(200, text=body)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        pages = list(CisaCrawler(client, pause=0).pages())
    assert len(pages) == 2
    assert visited[1].endswith("?page=1")
    record = pages[0][1][0]
    assert record.title == "Log4Shell"
    assert record.description == "Remote execution"
    assert record.action == "Upgrade"
    assert record.cwes == ["CWE-502"]
    assert record.references == ["https://example.org/advisory"]


@pytest.mark.parametrize(
    "body", ["<html>Access denied</html>", HTML.replace("Date Added:", "Missing:")]
)
def test_crawler_rejects_invalid_pages(body):
    from app.infrastructure.cisa import CisaCrawler

    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text=body))
    ) as client:
        with pytest.raises(ValueError):
            list(CisaCrawler(client, pause=0).pages())


def test_crawler_limits_pages_and_rejects_unsafe_next_link():
    from app.infrastructure.cisa import CisaCrawler

    body = HTML + '<a rel="next" href="https://example.org/">Next</a>'
    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text=body))
    ) as client:
        assert len(list(CisaCrawler(client, pause=0).pages(max_pages=1))) == 1
        with pytest.raises(ValueError, match="Paginação"):
            list(CisaCrawler(client, pause=0).pages())


@pytest.mark.parametrize("status", [403, 429, 503])
def test_crawler_stops_on_blocking_or_exhausted_errors(status, monkeypatch):
    from app.infrastructure.cisa import CisaCrawler

    monkeypatch.setattr("app.infrastructure.cisa.time.sleep", lambda _: None)
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(status))) as client:
        with pytest.raises(httpx.HTTPStatusError):
            list(CisaCrawler(client).pages())


@pytest.mark.integration
def test_collection_use_case_reports_progress_and_recollection(repository, vulnerability):
    from app.application.collect import Collect

    class Source:
        def pages(self, max_pages=0):
            yield "https://www.cisa.gov/catalog", [vulnerability]

    progress = []
    result = Collect(Source(), repository).run(progress=progress.append, baseline=True)
    assert result == {"pages": 1, "new": 1, "changed": 0, "unchanged": 0}
    assert progress[-1]["new"] == 1
    assert Collect(Source(), repository).run()["unchanged"] == 1
