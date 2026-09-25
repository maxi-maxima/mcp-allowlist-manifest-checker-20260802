# mcp-allowlist-manifest-checker

A tiny CLI for the new MCP-heavy world: it checks a manifest-like JSON file for unsafe tool grants, path escapes, and network exposure before you hand it to an agent.

## Pain point
Teams are adopting MCP quickly, but permissions are easy to over-grant. A single wildcard tool or unsafe path can quietly expand an agent’s blast radius.

## Why now
MCP is becoming a standard integration layer, and security reviews need a fast pre-flight check that works locally, in CI, and in code review.

## Install
No dependencies. Use Python 3.11+.

## Run
```bash
python main.py --manifest sample-manifest.json
```

JSON and TOML manifests are supported:
```bash
python main.py --manifest sample-manifest.toml
```

Use strict mode when CI should reject manifests that declare tools but forget to declare an explicit allowlist:
```bash
python main.py --manifest sample-manifest.json --require-allowlist --json
```

Tool entries may be objects (`{"name": "read_file"}`) or compact strings (`"read_file"`), so the checker works with both verbose and minimal manifest styles.

Require every tool grant to explain why it exists:
```bash
python main.py --manifest sample-manifest.json --require-tool-reasons
```

Use object entries such as `{"name": "read_file", "reason": "Read project documentation"}`. Compact string entries are reported as missing a reason when this policy is enabled.

Export SARIF when a code-scanning or CI gate should annotate unsafe manifest grants:
```bash
python main.py --manifest sample-manifest.json --format sarif > results.sarif
```

Apply a client preset when reviewing manifests for a common MCP client:
```bash
python main.py --manifest sample-manifest.json --preset claude-desktop
```

Available presets are `claude-desktop`, `codex`, and `cursor`. Presets require an explicit `allowed_tools` list and reject wildcard tool grants such as `*`, `all`, and `all_tools`.

## Example
Input:
```json
{
  "server": "demo",
  "allowed_tools": ["read_file", "list_files"],
  "tools": [{"name": "read_file"}, {"name": "shell"}],
  "paths": ["./project", "../secrets"],
  "network": true
}
```

Output:
```text
3 issue(s) found
- tool not on allowlist: shell
- unsafe path outside workspace: ../secrets
- network access is enabled
```

## Test
```bash
python -m unittest discover -s tests -v
```
