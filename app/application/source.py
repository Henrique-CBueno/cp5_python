from typing import Iterable, Protocol

from app.domain.vulnerability import Vulnerability


class VulnerabilitySource(Protocol):
    def pages(self, max_pages: int = 0) -> Iterable[tuple[str, list[Vulnerability]]]: ...
