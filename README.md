# zscanner

这是我用 Python 编写的一个多目标 TCP 扫描器项目。我希望它保持轻量、清楚、可读，同时支持日常扫描时常用的 CIDR 目标、并发扫描、服务名称提示、Banner 读取，以及 JSON/CSV 输出。

这个项目会继续保持独立可用，但接口设计也会兼顾后续的 AIScanner：AIScanner 会把 zscanner 作为底层侦察模块，用它完成目标解析、端口扫描、开放端口过滤、Web URL 生成和轻量服务识别。

请只扫描自己拥有或已获得授权的系统。

## 安装

需要 Python 3.10 或更高版本。

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
```

## 使用

```bash
zscanner scan 127.0.0.1 -p 22,80,443
zscanner scan 192.168.1.0/24 -p 80,443 -w 100 --service
zscanner scan @targets.txt -p @ports.txt --json > scan.json
zscanner version
```

旧版单命令写法仍然可用：

```bash
python -m zscanner 127.0.0.1 -p 22,80,443
```

## 目标

目标可以是主机名、IP 地址、逗号分隔列表、CIDR 网段，或 `@文件`：

```text
127.0.0.1
example.com
127.0.0.1,192.168.1.10
192.168.1.0/24
@targets.txt
```

CIDR 使用 Python 标准库 `ipaddress` 展开。默认最多允许 256 个目标、10,000 个扫描任务；扫描任务数等于目标数乘以端口数。需要更大范围时，可以显式调整 `--max-targets` 和 `--max-tasks`。

## 端口

```text
80
22,80,443
1-1024
22,80,8000-8010
@ports.txt
```

`@文件` 输入中，空行和以 `#` 开头的行会被忽略。

## 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-p`, `--ports` | `1-1024` | 端口表达式或 `@文件` |
| `-t`, `--timeout` | `1.0` | 单个端口连接超时时间，单位为秒 |
| `-w`, `--workers` | `1` | 并发工作线程数 |
| `--max-targets` | `256` | 最大目标数量 |
| `--max-tasks` | `10000` | 最大扫描任务数量 |
| `--all` | 关闭 | 显示关闭端口 |
| `--service` | 关闭 | 显示常见服务名称 |
| `--banner` | 关闭 | 读取开放端口的 Banner |
| `--json` | 关闭 | 输出 JSON |
| `--csv` | 关闭 | 输出 CSV |

多目标文本输出会按主机分组：

```text
Host: 192.168.1.10
   80/tcp  open        0.31 ms  http

Host: 192.168.1.11
  443/tcp  open        0.52 ms  https

Open ports: 2
```

## Python API

```python
from zscanner import ScanOptions, open_only, parse_ports, parse_targets, result_to_url, scan_many

targets = parse_targets("127.0.0.1,192.168.1.0/30")
ports = parse_ports("22,80,443")
options = ScanOptions(workers=50, timeout=0.5, banner_timeout=0.3, identify_service=True)

for result in open_only(scan_many(targets, ports, options)):
    print(result.as_dict(), result_to_url(result))
```

扫描常见 Web 端口：

```python
from zscanner import parse_targets, scan_web_targets

results = scan_web_targets(parse_targets("127.0.0.1"))
```

单独读取 Banner：

```python
from zscanner import grab_banner

banner = grab_banner("127.0.0.1", 22)
print(banner.text)
```

## 开发

```bash
pytest --cov=src/zscanner --cov-report=term-missing
ruff check .
mypy src
python -m pip wheel . --no-deps -w dist
```

## 路线图

- `zscanner wizard` 交互式命令行向导
- 面向重复实验环境的扫描配置
- 更丰富的可选服务探测

## 许可证

[MIT](LICENSE)
