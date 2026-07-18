"""Queue-driven worker pool for concurrent port scanning."""

import queue
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zscanner.scanner import ScanResult

ResultCallback = Callable[["ScanResult"], None]
PortScanner = Callable[[str, int, float], "ScanResult"]
Task = tuple[int, str, int]
ScanTask = tuple[str, int]


class ScanPool:
    """Scan ports with a bounded number of worker threads."""

    def __init__(self, workers: int = 100, on_result: ResultCallback | None = None) -> None:
        if workers < 1:
            raise ValueError("workers must be at least 1")
        self.workers = workers
        self.on_result = on_result

    def scan(
        self,
        host: str,
        ports: list[int],
        timeout: float = 1.0,
        port_scanner: PortScanner | None = None,
    ) -> list["ScanResult"]:
        """Scan concurrently and return results in the input order."""
        return self.scan_tasks([(host, port) for port in ports], timeout, port_scanner)

    def scan_tasks(
        self,
        scan_tasks: list[ScanTask],
        timeout: float = 1.0,
        port_scanner: PortScanner | None = None,
    ) -> list["ScanResult"]:
        """Scan host/port tasks concurrently and return results in input order."""
        if not scan_tasks:
            return []

        from zscanner.scanner import ScanResult, scan_port

        scan_one = port_scanner or scan_port

        tasks: queue.Queue[Task | None] = queue.Queue()
        results: list[ScanResult | None] = [None] * len(scan_tasks)
        errors: list[tuple[int, Exception]] = []
        lock = threading.Lock()
        worker_count = min(self.workers, len(scan_tasks))

        for index, (host, port) in enumerate(scan_tasks):
            tasks.put((index, host, port))
        for _ in range(worker_count):
            tasks.put(None)

        def worker() -> None:
            while True:
                task = tasks.get()
                try:
                    if task is None:
                        return
                    index, task_host, port = task
                    try:
                        result = scan_one(task_host, port, timeout)
                    except Exception as exc:
                        with lock:
                            errors.append((index, exc))
                    else:
                        results[index] = result
                        if self.on_result:
                            try:
                                self.on_result(result)
                            except Exception as exc:
                                with lock:
                                    errors.append((index, exc))
                finally:
                    tasks.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        if errors:
            raise min(errors, key=lambda item: item[0])[1]
        if any(result is None for result in results):
            raise RuntimeError("scan worker did not produce a result")
        return [result for result in results if result is not None]
