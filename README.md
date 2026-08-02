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

## Roadmap
- Add TOML support for common agent config files
- Export SARIF for CI gates
- Add presets for common MCP clients
