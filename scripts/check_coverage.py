"""Verifica separadamente a cobertura de linhas e de decisões do backend."""

import json
from pathlib import Path

totals = json.loads(Path(".coverage.json").read_text())["totals"]
lines = 100 * totals["covered_lines"] / totals["num_statements"]
branches = 100 * totals["covered_branches"] / totals["num_branches"]
print(f"Linhas: {lines:.2f}% · Branches: {branches:.2f}% · Meta: 85% em ambas")
raise SystemExit(0 if min(lines, branches) >= 85 else 1)
