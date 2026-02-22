"""
calm_parser/calm_parser.py
==========================
Parses one or more CALM JSON files and extracts:
  - Nodes and their types
  - Controls with full config
  - Relationships
  - Declared frameworks, technologies, and compliance references
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from models import CalmControl, CalmRelationship, CalmSummary

log = logging.getLogger(__name__)


class CalmParser:
    """
    Parses CALM architecture JSON files into a CalmSummary.
    Supports multiple files — controls are merged into a single list.
    """

    def __init__(self, calm_paths: list[str]) -> None:
        self.calm_paths = calm_paths

    # ── Public API ────────────────────────────────────────────────

    def parse(self) -> CalmSummary:
        summary = CalmSummary(source_files=self.calm_paths)

        for path_str in self.calm_paths:
            path = Path(path_str)
            if not path.exists():
                raise FileNotFoundError(f"CALM file not found: {path}")
            log.debug(f"Parsing CALM file: {path}")
            data = json.loads(path.read_text(encoding="utf-8"))
            self._extract(data, summary)

        # Deduplicate
        summary.declared_frameworks = sorted(set(summary.declared_frameworks))
        summary.declared_compliance  = sorted(set(summary.declared_compliance))

        log.debug(f"Controls parsed: {[c.control_id for c in summary.controls]}")
        return summary

    # ── Internal ──────────────────────────────────────────────────

    def _extract(self, data: dict[str, Any], summary: CalmSummary) -> None:
        # Top-level metadata
        metadata = data.get("metadata", {})
        framework = metadata.get("framework", "")
        if framework:
            summary.declared_frameworks.append(framework)

        # Nodes
        for node in data.get("nodes", []):
            node_id   = node.get("unique-id", "")
            node_name = node.get("name", node_id)
            node_type = node.get("node-type", "unknown")

            summary.nodes.append({
                "id": node_id,
                "name": node_name,
                "type": node_type,
                "description": node.get("description", ""),
            })

            # Controls within each node
            for ctrl_id, ctrl_data in node.get("controls", {}).items():
                requirements = ctrl_data.get("requirements", [{}])
                req          = requirements[0] if requirements else {}
                config       = req.get("config", {})

                control = CalmControl(
                    control_id      = f"{node_id}/{ctrl_id}",
                    node_id         = node_id,
                    node_name       = node_name,
                    node_type       = node_type,
                    description     = ctrl_data.get("description", ctrl_id),
                    config          = config,
                    requirement_url = req.get("requirement-url", ""),
                )
                summary.controls.append(control)

                # Harvest compliance framework mentions
                cf = config.get("compliance-framework", "")
                if cf:
                    summary.declared_compliance.append(cf)

                # Harvest framework references from config values
                for v in config.values():
                    if isinstance(v, str):
                        summary.declared_frameworks.append(v)

        # Relationships
        for rel in data.get("relationships", []):
            props = rel.get("properties", {}) or {}
            summary.relationships.append(
                CalmRelationship(
                    source            = rel.get("source", {}).get("node", ""),
                    target            = rel.get("destination", {}).get("node", ""),
                    relationship_type = rel.get("relationship-type", "unknown"),
                    protocol          = rel.get("protocol", props.get("protocol", "")),
                    properties        = props,
                )
            )
