import re
import time
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.domain.vulnerability import Vulnerability

CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EXPORT = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaCrawler:
    def __init__(self, client: httpx.Client, pause: float = 1.5):
        self.client, self.pause = client, pause

    def pages(self, max_pages: int = 0):
        url, visited = CATALOG, set()
        unique_ids, expected_total = set(), None
        while url and (not max_pages or len(visited) < max_pages):
            if url in visited or urlparse(url).netloc != "www.cisa.gov":
                raise ValueError("Paginação inválida na fonte CISA")
            visited.add(url)
            response = None
            for attempt in range(3):
                try:
                    response = self.client.get(url)
                    if response.status_code in (403, 429):
                        response.raise_for_status()
                    response.raise_for_status()
                    break
                except httpx.HTTPError as exc:
                    status = getattr(getattr(exc, "response", None), "status_code", 0)
                    if status in (403, 429) or attempt == 2:
                        raise
                    time.sleep(2**attempt)
            soup = BeautifulSoup(response.text, "html.parser")
            total = re.search(r"of\s+([\d,]+)\s+results", soup.get_text(" ", strip=True))
            if total:
                expected_total = int(total[1].replace(",", ""))
            cards = soup.select("article.c-teaser")
            if not cards:
                raise ValueError("A página CISA não contém registros; verifique a fonte")
            records = []
            for card in cards:
                vendor, product = (
                    card.select_one(".c-teaser__meta").get_text(strip=True).split("|", 1)
                )
                name = card.select_one(".c-teaser__vuln-name")
                description = name.select_one("span").get_text(" ", strip=True)
                title = " ".join(
                    str(t).strip() for t in name.find_all(string=True, recursive=False)
                ).rstrip(": ")
                text = card.get_text(" ", strip=True)
                added = re.search(r"Date Added:\s*(\d{4}-\d{2}-\d{2})", text)
                due = re.search(r"Due Date:\s*(\d{4}-\d{2}-\d{2})", text)
                ransomware = re.search(r"Ransomware Campaigns\?\s*(Known|Unknown)", text)
                if not all((added, due, ransomware)):
                    raise ValueError("Campos obrigatórios ausentes na fonte CISA")
                action = card.select_one(".c-teaser__teaser-action").get_text(" ", strip=True)
                records.append(
                    Vulnerability(
                        cve_id=card.select_one(".c-teaser__title a").get_text(strip=True),
                        vendor=vendor,
                        product=product,
                        title=title,
                        description=description,
                        action=action.removeprefix("Action:").strip(),
                        date_added=added[1],
                        due_date=due[1],
                        ransomware=ransomware[1],
                        source_url=url,
                        cwes=[c.get_text(strip=True) for c in card.select(".c-teaser__cwe")],
                        references=[a["href"] for a in card.select(".c-teaser__notes a[href]")],
                    )
                )
            unique_ids.update(record.cve_id for record in records)
            yield url, records
            following = soup.select_one('a[rel="next"]')
            url = urljoin(url, following["href"]) if following else None
            if url and self.pause:
                time.sleep(self.pause)
        if not max_pages and expected_total and len(unique_ids) < expected_total:
            # Reconciliação complementar: a paginação HTML pode repetir CVEs.
            response = self.client.get(EXPORT)
            response.raise_for_status()
            exported = response.json()
            missing = []
            for item in exported["vulnerabilities"]:
                if item["cveID"] in unique_ids:
                    continue
                missing.append(
                    Vulnerability(
                        cve_id=item["cveID"],
                        vendor=item["vendorProject"],
                        product=item["product"],
                        title=item["vulnerabilityName"],
                        description=item["shortDescription"],
                        action=item["requiredAction"],
                        date_added=item["dateAdded"],
                        due_date=item["dueDate"],
                        ransomware=item["knownRansomwareCampaignUse"],
                        source_url=EXPORT,
                        references=re.findall(r"https?://[^\s;]+", item.get("notes", "")),
                        cwes=item.get("cwes", []),
                    )
                )
            unique_ids.update(record.cve_id for record in missing)
            if len(unique_ids) < exported["count"]:
                raise ValueError(
                    f"Catálogo incompleto: {len(unique_ids)} CVEs únicos para {exported['count']} resultados informados pela fonte"
                )
            yield EXPORT, missing
