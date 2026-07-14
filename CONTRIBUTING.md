# Contributing

感谢参与 zscanner。请只对你拥有或获准测试的目标运行扫描器。

## 开发流程

1. Fork 仓库并从 `main` 创建功能分支。
2. 创建虚拟环境并运行 `python -m pip install -e ".[dev]"`。
3. 为行为变更添加或更新测试。
4. 运行 `pytest`、`ruff check .` 和 `mypy src`。
5. 提交说明清晰、范围单一的 Pull Request。

请勿提交密钥、扫描结果、个人数据或未经授权目标的信息。漏洞报告请遵循 [SECURITY.md](SECURITY.md)。
