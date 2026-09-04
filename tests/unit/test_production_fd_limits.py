"""Production compose safeguards against file-descriptor exhaustion."""

from pathlib import Path

import pytest


@pytest.mark.unit
def test_production_compose_sets_a_high_mcp_nofile_limit():
    compose = (Path(__file__).parents[2] / "docker-compose.production.yml").read_text(
        encoding="utf-8"
    )

    assert "ulimits:" in compose
    assert 'soft: "${MCP_NOFILE_SOFT:-65536}"' in compose
    assert 'hard: "${MCP_NOFILE_HARD:-65536}"' in compose
