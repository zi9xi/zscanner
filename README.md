# zscanner

一个用于学习 Python 网络编程的简单 TCP 端口扫描器，核心使用标准库 `socket`。

> 仅扫描自己拥有或已获得授权的设备。

## 功能

- 扫描 IPv4 地址或主机名
- 支持单个端口、多个端口和端口范围
- 支持从 `@文件` 读取端口
- 可设置连接超时
- 支持可配置的多线程并发扫描
- 提供扫描进度回调
- 显示端口状态和连接耗时

不支持 UDP、IPv6、服务识别、网段扫描和漏洞检测。

## 安装

需要 Python 3.10 或更高版本，无运行时第三方依赖。

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
```

## 使用

```bash
python -m zscanner <目标> -p <端口>
```

### 示例

扫描一个端口：

```bash
python -m zscanner 127.0.0.1 -p 80
```

扫描多个端口：

```bash
python -m zscanner localhost -p 22,80,443
```

扫描端口范围：

```bash
python -m zscanner 192.168.1.10 -p 1-1024
```

混合端口并设置 0.5 秒超时：

```bash
python -m zscanner 192.168.1.10 -p 22,80,443,8000-8010 -t 0.5
```

使用 50 个工作线程：

```bash
python -m zscanner 192.168.1.10 -p 1-1024 -t 0.5 -w 50
```

从文件读取端口：

```text
# ports.txt
22,80,443
8000-8010
```

```bash
python -m zscanner 127.0.0.1 -p @ports.txt -w 20
```

默认只显示开放端口。显示关闭端口：

```bash
python -m zscanner 127.0.0.1 -p 22,80,443 --all
```

### 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `host` | 必填 | IPv4 地址或主机名 |
| `-p`, `--ports` | `1-1024` | 端口，如 `80`、`22,80`、`1-1024` |
| `-t`, `--timeout` | `1.0` | 每个端口的超时秒数 |
| `-w`, `--workers` | `1` | 工作线程数；`1` 表示顺序扫描 |
| `--all` | 关闭 | 显示关闭端口 |

可能的输出：

```text
   80/tcp  open        0.31 ms
  443/tcp  closed      0.52 ms
Open ports: 1
```

## Python API

```python
from zscanner import parse, scan, scan_port

result = scan_port("127.0.0.1", 80, timeout=0.5)
print(result.is_open)

ports = parse("22,80,443,8000-8010")

for result in scan("127.0.0.1", ports, workers=20):
    print(result.port, result.is_open, result.latency_ms)
```

进度回调接收“已完成数量”和“总数量”：

```python
results = scan(
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
├── cli.py         # 命令行
├── concurrent.py  # 队列驱动线程池
├── ports.py       # 端口解析和文件输入
├── scanner.py     # Socket 扫描与执行入口
└── __main__.py    # python -m zscanner 入口
```

## 测试

```bash
pytest --cov=src/zscanner --cov-report=term-missing
ruff check .
mypy src
```

## License

[MIT](LICENSE)
