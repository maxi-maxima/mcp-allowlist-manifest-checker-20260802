from __future__ import annotations

import argparse
import json
import tomllib
from pathlib import Path
from typing import Any

UNSAFE_TOOL_NAMES = {"shell", "exec", "write", "delete", "network", "download"}


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


def check_manifest(manifest: dict[str, Any], require_allowlist: bool = False) -> list[str]:
    issues: list[str] = []
    allowed = {normalize_tool_name(tool) for tool in manifest.get("allowed_tools", [])}
    allowed.discard("")
    tools = iter_tools(manifest)
    if require_allowlist and tools and not allowed:
        issues.append("allowed_tools is required when tools are declared")
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Check MCP-style manifests for unsafe grants.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "--require-allowlist",
        action="store_true",
        help="flag manifests that declare tools without an allowed_tools list",
    )
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    issues = check_manifest(manifest, require_allowlist=args.require_allowlist)
    if args.json:
        print(json.dumps({"server": manifest.get("server"), "issues": issues}, indent=2, ensure_ascii=False))
    else:
        print(format_report(manifest, issues))
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
