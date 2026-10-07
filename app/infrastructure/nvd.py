import time

import httpx

ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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
            response = self.client.get(ENDPOINT, params={"cveIds": ",".join(ids[offset:offset+100])}, headers={"apiKey": self.api_key} if self.api_key else {})
            response.raise_for_status()
            for item in response.json()["vulnerabilities"]:
                cve = item["cve"]
                assessments = []
                for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    for metric in cve.get("metrics", {}).get(key, []):
                        score = metric["cvssData"]
                        assessments.append({"version": score["version"], "score": score["baseScore"], "severity": score.get("baseSeverity", metric.get("baseSeverity", "UNKNOWN")), "vector": score["vectorString"], "source": metric["source"], "type": metric["type"], "data": score})
                assessments.sort(key=lambda a: (-float(a["version"]), a["type"] != "Primary", a["source"] != "nvd@nist.gov", a["source"]))
                result[cve["id"]] = {"assessments": assessments, "primary": assessments[0] if assessments else None, **{k: cve.get(k, []) for k in ("descriptions", "references", "weaknesses", "configurations")}, "status": cve.get("vulnStatus", "Not supplied"), "published": cve.get("published"), "last_modified": cve.get("lastModified"), "source_url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"}
        return result
