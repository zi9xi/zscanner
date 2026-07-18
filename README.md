# zscanner

zscanner 是一个基于 Python 标准库构建的多目标 TCP 扫描器，支持并发端口扫描、服务名称识别、Banner 抓取，以及 JSON/CSV 结果输出。

> 仅扫描自己拥有或已获得授权的目标。未经授权的扫描可能违反法律或服务条款。

## 功能

- TCP Connect 端口扫描
- 单目标、多目标、CIDR 网段和 `@文件` 目标输入
- 单端口、多端口、端口范围和 `@文件` 端口输入
- 多目标 × 多端口任务扫描
- 可配置连接超时
- 可配置多线程并发扫描
- `--max-targets` 和 `--max-tasks` 安全限制
- 常见端口服务识别
- 对开放端口进行 Banner 抓取
- 文本、JSON、CSV 输出
- Python API 可直接集成到其他脚本

当前不支持 UDP、IPv6、漏洞检测、认证扫描和交互式向导。交互式命令行向导计划在 `0.4.1` 增加。

## 安装

需要 Python 3.10 或更高版本。运行时无第三方依赖。

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
```

## 快速开始

推荐使用 `scan` 子命令：

```bash
zscanner scan 127.0.0.1 -p 22,80,443
```

也可以继续使用兼容旧版本的写法：

```bash
python -m zscanner 127.0.0.1 -p 22,80,443
```

扫描多个目标：

```bash
zscanner scan 127.0.0.1,192.168.1.10 -p 22,80,443 -w 50
```

扫描 CIDR 网段：

```bash
zscanner scan 192.168.1.0/24 -p 80,443 -w 100 --service
```

从文件读取目标：

```text
# targets.txt
127.0.0.1
192.168.1.10
192.168.1.0/30
```

```bash
zscanner scan @targets.txt -p 22,80,443 -w 50
```

输出 JSON：

```bash
zscanner scan 192.168.1.0/24 -p 80,443 -w 100 --service --json > scan.json
```

输出 CSV：

```bash
zscanner scan 192.168.1.0/24 -p 80,443 -w 100 --service --csv > scan.csv
```

抓取开放端口 Banner：

```bash
zscanner scan 127.0.0.1 -p 22,80,443 --banner
```

查看版本：

```bash
zscanner version
```

## 目标输入

支持以下格式：

```text
127.0.0.1
example.com
127.0.0.1,192.168.1.10
192.168.1.0/24
@targets.txt
```

CIDR 会展开为可用主机地址。例如 `192.168.1.0/30` 会展开为：

```text
192.168.1.1
192.168.1.2
```

默认最多解析 256 个目标。可以通过 `--max-targets` 调整。

## 端口输入

支持以下格式：

```text
80
22,80,443
1-1024
22,80,8000-8010
@ports.txt
```

端口文件示例：

```text
# ports.txt
22,80,443
8000-8010
```

## 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `targets` | 必填 | 目标、逗号分隔目标、CIDR 或 `@文件` |
| `-p`, `--ports` | `1-1024` | 端口表达式或 `@文件` |
| `-t`, `--timeout` | `1.0` | 每个端口的超时秒数 |
| `-w`, `--workers` | `1` | 工作线程数；`1` 表示顺序扫描 |
| `--max-targets` | `256` | 最大目标数量 |
| `--max-tasks` | `10000` | 最大扫描任务数，任务数 = 目标数 × 端口数 |
| `--open` | 开启 | 只显示开放端口 |
| `--all` | 关闭 | 显示开放和关闭端口 |
| `--service` | 关闭 | 显示常见端口服务名称 |
| `--banner` | 关闭 | 对开放端口抓取 Banner，并自动显示服务名称 |
| `--json` | 关闭 | 输出 JSON |
| `--csv` | 关闭 | 输出 CSV |

## 输出示例

多目标文本输出会按主机分组：

```text
Host: 192.168.1.10
   80/tcp  open        0.31 ms  http

Host: 192.168.1.11
  443/tcp  open        0.52 ms  https

Open ports: 2
```

JSON 输出：

```json
[
  {
    "host": "192.168.1.10",
    "port": 80,
    "is_open": true,
    "latency_ms": 0.31,
    "error": null,
    "service": "http",
    "banner": "HTTP/1.0 200 OK"
  }
]
```

CSV 输出：

```csv
host,port,state,latency_ms,service,banner,error
192.168.1.10,80,open,0.31,http,HTTP/1.0 200 OK,
```

## Python API

```python
from zscanner import parse, parse_targets, scan_many

targets = parse_targets("127.0.0.1,192.168.1.0/30")
ports = parse("22,80,443")

results = scan_many(
    targets,
    ports,
    timeout=0.5,
    workers=50,
    identify_service=True,
    grab_banner=True,
)

for item in results:
    print(item.host, item.port, item.is_open, item.service, item.banner)
```

旧的单目标 API 仍然可用：

```python
from zscanner import scan

results = scan("127.0.0.1", [22, 80, 443], workers=20)
```

进度回调接收“已完成数量”和“总数量”：

```python
scan_many(
    ["127.0.0.1", "192.168.1.10"],
    [22, 80, 443],
    workers=10,
    on_progress=lambda done, total: print(f"{done}/{total}"),
)
```

返回结果始终按“目标顺序 × 端口顺序”排列，和线程完成顺序无关。

## 项目结构

```text
src/zscanner/
├── cli.py          # 命令行入口
├── concurrent.py   # 队列驱动任务池
├── fingerprint.py  # 常见端口服务识别
├── output.py       # 文本、JSON、CSV 输出
├── ports.py        # 端口解析和 @文件 输入
├── probe.py        # Banner 抓取
├── scanner.py      # TCP Connect 扫描核心
├── targets.py      # 目标解析、CIDR 展开和安全限制
└── __main__.py     # python -m zscanner 入口
```

## 路线图

`0.4.1` 计划增加交互式命令行向导：

```bash
zscanner wizard
```

向导会逐步询问目标、端口、线程数、超时、是否启用服务识别和 Banner 抓取。这个功能会复用 `0.4.0` 的 `targets`、`ports`、`scan_many` 和 `output` 模块，不改变扫描核心。

## 开发与测试

```bash
pytest --cov=src/zscanner --cov-report=term-missing
ruff check .
mypy src
python -m build
```

## License

[MIT](LICENSE)
