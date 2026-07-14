# zscanner

一个用于学习 Python 网络编程的简单 TCP 端口扫描器，核心使用标准库 `socket`。

> 仅扫描自己拥有或已获得授权的设备。

## 功能

- 扫描 IPv4 地址或主机名
- 支持单个端口、多个端口和端口范围
- 可设置连接超时
- 显示端口状态和连接耗时
- 当前顺序扫描，后续可将循环替换为线程池

不支持 UDP、IPv6、服务识别、网段扫描和漏洞检测。

## 安装

需要 Python 3.10 或更高版本。

### Windows

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## 使用

```bash
zscanner <目标> -p <端口> [选项]
```

也可以使用：

```bash
python -m zscanner <目标> -p <端口>
```

### 示例

扫描一个端口：

```bash
zscanner 127.0.0.1 -p 80
```

扫描多个端口：

```bash
zscanner localhost -p 22,80,443
```

扫描端口范围：

```bash
zscanner 192.168.1.10 -p 1-1024
```

混合端口并设置 0.5 秒超时：

```bash
zscanner 192.168.1.10 -p 22,80,443,8000-8010 -t 0.5
```

默认只显示开放端口。显示关闭端口：

```bash
zscanner 127.0.0.1 -p 22,80,443 --all
```

### 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `host` | 必填 | IPv4 地址或主机名 |
| `-p`, `--ports` | `1-1024` | 端口，如 `80`、`22,80`、`1-1024` |
| `-t`, `--timeout` | `1.0` | 每个端口的超时秒数 |
| `--all` | 关闭 | 显示关闭端口 |

可能的输出：

```text
   80/tcp  open        0.31 ms
  443/tcp  closed      0.52 ms
Open ports: 1
```

## Python API

```python
from zscanner import scan, scan_port

result = scan_port("127.0.0.1", 80, timeout=0.5)
print(result.is_open)

for result in scan("127.0.0.1", [22, 80, 443]):
    print(result.port, result.is_open, result.latency_ms)
```

## 项目结构

```text
src/zscanner/
├── cli.py       # 参数解析和命令行
├── scanner.py   # Socket 扫描核心
└── __main__.py  # python -m zscanner 入口
tests/           # 单元测试
```

## 开发

```bash
pytest
ruff check .
mypy src
```

VS Code 打开项目后，选择 `.venv` 中的 Python 解释器即可运行和调试。

## License

[MIT](LICENSE)
