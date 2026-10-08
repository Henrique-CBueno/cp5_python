import time
from datetime import UTC, datetime

import httpx

from app.domain.assessment import CvssAssessment

ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def utc_timestamp(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC).isoformat()


class NvdClient:
    def __init__(self, client: httpx.Client, api_key="", pause=6.1):
        self.client, self.api_key, self.pause = client, api_key, pause
        self.last_request = 0

    def fetch(self, ids: list[str]) -> dict:
        result = {}
        for offset in range(0, len(ids), 100):
            delay = self.pause - (time.monotonic() - self.last_request)
            if delay > 0:
                time.sleep(delay)
            self.last_request = time.monotonic()
            response = self.client.get(
                ENDPOINT,
                params={"cveIds": ",".join(ids[offset : offset + 100])},
                headers={"apiKey": self.api_key} if self.api_key else {},
            )
            response.raise_for_status()
            for item in response.json()["vulnerabilities"]:
                cve = item["cve"]
                assessments = []
                for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    for metric in cve.get("metrics", {}).get(key, []):
                        score = metric["cvssData"]
                        assessments.append(
                            CvssAssessment(
                                version=score["version"],
                                score=score["baseScore"],
                                severity=score.get(
                                    "baseSeverity", metric.get("baseSeverity", "UNKNOWN")
                                ),
                                vector=score["vectorString"],
                                source=metric["source"],
                                type=metric["type"],
                                data=score,
                            )
                        )
                assessments = [
                    assessment.model_dump(mode="json")
                    for assessment in sorted(assessments, key=lambda a: a.precedence)
                ]
                result[cve["id"]] = {
                    "assessments": assessments,
                    "primary": assessments[0] if assessments else None,
                    **{
                        k: cve.get(k, [])
                        for k in ("descriptions", "references", "weaknesses", "configurations")
                    },
                    "status": cve.get("vulnStatus", "Not supplied"),
                    "published": utc_timestamp(cve.get("published")),
                    "last_modified": utc_timestamp(cve.get("lastModified")),
                    "source_url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                }
        return result
