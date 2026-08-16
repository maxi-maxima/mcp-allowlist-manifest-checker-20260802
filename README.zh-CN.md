# mcp-allowlist-manifest-checker

一个轻量 CLI，用来在把 MCP 配置交给智能体前，先检查工具权限、路径越界和网络暴露风险。

## 解决的痛点
MCP 普及很快，但权限往往容易给多。一个通配工具、一个越界路径，就可能悄悄扩大智能体的攻击面。

## 为什么现在值得做
MCP 正在变成常见集成层，安全审查需要一个本地、CI、代码评审都能快速跑的预检工具。

## 安装
无额外依赖，使用 Python 3.11+ 即可。

## 运行
```bash
python main.py --manifest sample-manifest.json
```

JSON 和 TOML manifest 都支持：
```bash
python main.py --manifest sample-manifest.toml
```

如果 CI 需要拒绝“声明了 tools 但没有显式 allowed_tools”的配置，可以开启严格模式：
```bash
python main.py --manifest sample-manifest.json --require-allowlist --json
```

工具条目既可以写成对象（`{"name": "read_file"}`），也可以写成紧凑字符串（`"read_file"`），方便兼容不同风格的 manifest。

当需要接入代码扫描或 CI 阻断时，可以导出 SARIF：
```bash
python main.py --manifest sample-manifest.json --format sarif > results.sarif
```

## 示例
输入：
```json
{
  "server": "demo",
  "allowed_tools": ["read_file", "list_files"],
  "tools": [{"name": "read_file"}, {"name": "shell"}],
  "paths": ["./project", "../secrets"],
  "network": true
}
```

输出：
```text
发现 3 个问题
- tool not on allowlist: shell
- unsafe path outside workspace: ../secrets
- network access is enabled
```

## 测试
```bash
python -m unittest discover -s tests -v
```

## 路线图
- 增加主流 MCP 客户端预设
