from __future__ import annotations

import argparse
import json
import tomllib
from pathlib import Path
from typing import Any

UNSAFE_TOOL_NAMES = {"shell", "exec", "write", "delete", "network", "download"}
WILDCARD_TOOL_NAMES = {"*", "all", "all_tools"}
CLIENT_PRESETS = {
    "claude-desktop": {
        "require_allowlist": True,
        "reject_wildcards": True,
    },
    "codex": {
        "require_allowlist": True,
        "reject_wildcards": True,
    },
    "cursor": {
        "require_allowlist": True,
        "reject_wildcards": True,
    },
}


def load_manifest(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".toml":
        return tomllib.loads(text)
    return json.loads(text)


def path_is_safe(entry: str) -> bool:
    candidate = Path(entry)
    if candidate.is_absolute():
        return False
    return ".." not in candidate.parts


def normalize_tool_name(tool: Any) -> str:
    if isinstance(tool, str):
        return tool
    if isinstance(tool, dict):
        return str(tool.get("name", ""))
    return ""


def iter_tools(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    tools = []
    for raw in manifest.get("tools", []):
        if isinstance(raw, str):
            tools.append({"name": raw})
        elif isinstance(raw, dict):
            tools.append(raw)
        else:
            tools.append({"name": "", "raw_type": type(raw).__name__})
    return tools


def check_manifest(
    manifest: dict[str, Any],
    require_allowlist: bool = False,
    require_tool_reasons: bool = False,
    preset: str | None = None,
) -> list[str]:
    issues: list[str] = []
    preset_config = CLIENT_PRESETS.get(preset or "", {})
    effective_require_allowlist = require_allowlist or bool(preset_config.get("require_allowlist"))
    reject_wildcards = bool(preset_config.get("reject_wildcards"))
    allowed = {normalize_tool_name(tool) for tool in manifest.get("allowed_tools", [])}
    allowed.discard("")
    tools = iter_tools(manifest)
    if effective_require_allowlist and tools and not allowed:
        issues.append("allowed_tools is required when tools are declared")
    if reject_wildcards:
        for name in sorted(allowed):
            if name.lower() in WILDCARD_TOOL_NAMES:
                issues.append(f"wildcard allowlist entry is not allowed by {preset} preset: {name}")
    for tool in tools:
        name = str(tool.get("name", ""))
        if not name:
            raw_type = tool.get("raw_type")
            if raw_type:
                issues.append(f"tool entry has unsupported type: {raw_type}")
            else:
                issues.append("tool entry is missing a name")
            continue
        if allowed and name not in allowed:
            issues.append(f"tool not on allowlist: {name}")
        if name in UNSAFE_TOOL_NAMES:
            issues.append(f"unsafe tool requested: {name}")
        if reject_wildcards and name.lower() in WILDCARD_TOOL_NAMES:
            issues.append(f"wildcard tool grant is not allowed by {preset} preset: {name}")
        reason = tool.get("reason")
        if require_tool_reasons and (not isinstance(reason, str) or not reason.strip()):
            issues.append(f"tool is missing a reason: {name}")
        if tool.get("dangerous"):
            issues.append(f"dangerous tool flag enabled: {name}")
    for entry in manifest.get("paths", []):
        if not path_is_safe(str(entry)):
            issues.append(f"unsafe path outside workspace: {entry}")
    if manifest.get("network"):
        issues.append("network access is enabled")
    return issues


def format_report(manifest: dict[str, Any], issues: list[str]) -> str:
    server = manifest.get("server", "unknown")
    if issues:
        lines = [f"{len(issues)} issue(s) found on {server}"]
        lines.extend(f"- {issue}" for issue in issues)
    else:
        lines = [f"0 issue(s) found on {server}", "manifest is within the declared allowlist"]
    return "\n".join(lines)


def rule_id_for_issue(issue: str) -> str:
    if issue.startswith("tool not on allowlist"):
        return "tool-not-on-allowlist"
    if issue.startswith("unsafe tool requested"):
        return "unsafe-tool"
    if issue.startswith("dangerous tool flag"):
        return "dangerous-tool-flag"
    if issue.startswith("unsafe path outside workspace"):
        return "unsafe-path"
    if issue == "network access is enabled":
        return "network-enabled"
    if issue.startswith("allowed_tools is required"):
        return "missing-allowlist"
    if issue.startswith("tool entry"):
        return "invalid-tool-entry"
    if issue.startswith("tool is missing a reason"):
        return "missing-tool-reason"
    if issue.startswith("wildcard"):
        return "wildcard-tool-grant"
    return "manifest-policy-issue"


def format_sarif(manifest_path: Path, manifest: dict[str, Any], issues: list[str]) -> dict[str, Any]:
    rules = {}
    results = []
    for issue in issues:
        rule_id = rule_id_for_issue(issue)
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": rule_id.replace("-", " ")}})
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": issue},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": manifest_path.as_posix()},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-allowlist-manifest-checker",
                        "informationUri": "https://github.com/maxi-maxima/mcp-allowlist-manifest-checker-20260802",
                        "rules": list(rules.values()),
                    }
                },
                "properties": {"server": manifest.get("server")},
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check MCP-style manifests for unsafe grants.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="output format")
    parser.add_argument(
        "--preset",
        choices=sorted(CLIENT_PRESETS),
        help="apply a stricter policy preset for a common MCP client",
    )
    parser.add_argument(
        "--require-allowlist",
        action="store_true",
        help="flag manifests that declare tools without an allowed_tools list",
    )
    parser.add_argument(
        "--require-tool-reasons",
        action="store_true",
        help="flag tool grants without a non-empty reason field",
    )
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    issues = check_manifest(
        manifest,
        require_allowlist=args.require_allowlist,
        require_tool_reasons=args.require_tool_reasons,
        preset=args.preset,
    )
    output_format = "json" if args.json else args.format
    if output_format == "json":
        payload = {"server": manifest.get("server"), "issues": issues}
        if args.preset:
            payload["preset"] = args.preset
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif output_format == "sarif":
        print(json.dumps(format_sarif(args.manifest, manifest, issues), indent=2, ensure_ascii=False))
    else:
        print(format_report(manifest, issues))
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
