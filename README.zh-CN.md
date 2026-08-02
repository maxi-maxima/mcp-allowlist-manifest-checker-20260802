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
- 增加常见 agent 配置的 TOML 支持
- 导出 SARIF 方便 CI 阻断
- 增加主流 MCP 客户端预设
