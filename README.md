# zscanner

zscanner 是一个基于 Python 标准库构建的 TCP 扫描器项目，支持并发端口扫描、服务名称识别、Banner 抓取，以及 JSON/CSV 结果输出。

> 仅扫描自己拥有或已获得授权的目标。未经授权的扫描可能违反法律或服务条款。

## 功能

- TCP Connect 端口扫描
- IPv4 地址或主机名目标
- 单端口、多端口、端口范围和混合端口输入
- 从 `@文件` 读取端口列表
- 可配置连接超时
- 可配置多线程并发扫描
- 常见端口服务识别
- 对开放端口进行 Banner 抓取
- 默认只显示开放端口，可选择显示全部端口
- 支持文本、JSON、CSV 输出
- Python API 可直接集成到其他脚本

当前不支持 UDP、IPv6、网段扫描、漏洞检测和认证扫描。

## 安装

需要 Python 3.10 或更高版本。运行时无第三方依赖。

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
```

也可以直接运行源码：

```bash
python -m zscanner 127.0.0.1 -p 80
```

## 快速开始

扫描常见端口：

```bash
python -m zscanner 127.0.0.1 -p 22,80,443
```

使用 50 个工作线程扫描端口范围：

```bash
python -m zscanner 192.168.1.10 -p 1-1024 -w 50 -t 0.5
```

显示服务名称：

```bash
python -m zscanner 127.0.0.1 -p 22,80,443 --service
```

抓取开放端口 Banner：

```bash
python -m zscanner 127.0.0.1 -p 22,80,443 --banner
```

输出 JSON：

```bash
python -m zscanner 127.0.0.1 -p 1-1000 -w 50 --service --json > scan.json
```

输出 CSV：

```bash
python -m zscanner 127.0.0.1 -p 1-1000 -w 50 --service --csv > scan.csv
```

显示关闭端口：

```bash
python -m zscanner 127.0.0.1 -p 22,80,443 --all
```

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

运行：

```bash
python -m zscanner 127.0.0.1 -p @ports.txt -w 20
```

## 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `host` | 必填 | IPv4 地址或主机名 |
| `-p`, `--ports` | `1-1024` | 端口表达式或 `@文件` |
| `-t`, `--timeout` | `1.0` | 每个端口的超时秒数 |
| `-w`, `--workers` | `1` | 工作线程数；`1` 表示顺序扫描 |
| `--open` | 开启 | 只显示开放端口 |
| `--all` | 关闭 | 显示开放和关闭端口 |
| `--service` | 关闭 | 显示常见端口服务名称 |
| `--banner` | 关闭 | 对开放端口抓取 Banner，并自动显示服务名称 |
| `--json` | 关闭 | 输出 JSON |
| `--csv` | 关闭 | 输出 CSV |

## 输出示例

文本输出：

```text
   80/tcp  open        0.31 ms  http
  443/tcp  open        0.52 ms  https
Open ports: 2
```

JSON 输出：

```json
[
  {
    "host": "127.0.0.1",
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
127.0.0.1,80,open,0.31,http,HTTP/1.0 200 OK,
```

## Python API

```python
from zscanner import parse, scan, scan_port

result = scan_port("127.0.0.1", 80, timeout=0.5, identify_service=True)
print(result.port, result.is_open, result.service)

ports = parse("22,80,443,8000-8010")
results = scan(
    "127.0.0.1",
    ports,
    timeout=0.5,
    workers=20,
    identify_service=True,
    grab_banner=True,
)

for item in results:
    print(item.port, item.is_open, item.service, item.banner)
```

进度回调接收“已完成数量”和“总数量”：

```python
scan(
    "127.0.0.1",
    [22, 80, 443],
    workers=3,
    on_progress=lambda done, total: print(f"{done}/{total}"),
)
```

无论线程完成顺序如何，返回结果始终与输入端口顺序一致。

## 项目结构

```text
src/zscanner/
├── cli.py          # 命令行入口
├── concurrent.py   # 队列驱动线程池
├── fingerprint.py  # 常见端口服务识别
├── output.py       # 文本、JSON、CSV 输出
├── ports.py        # 端口解析和 @文件 输入
├── probe.py        # Banner 抓取
├── scanner.py      # TCP Connect 扫描核心
└── __main__.py     # python -m zscanner 入口
```

## 开发与测试

```bash
pytest --cov=src/zscanner --cov-report=term-missing
ruff check .
mypy src
python -m build
```

## License

[MIT](LICENSE)
