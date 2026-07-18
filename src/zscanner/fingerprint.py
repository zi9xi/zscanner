"""Service name guesses for well-known TCP ports."""

_PORT_SERVICE_MAP: dict[int, tuple[str, str]] = {
    20: ("ftp-data", "FTP data transfer"),
    21: ("ftp", "File Transfer Protocol"),
    22: ("ssh", "Secure Shell"),
    23: ("telnet", "Telnet"),
    25: ("smtp", "Simple Mail Transfer Protocol"),
    53: ("dns", "Domain Name System"),
    80: ("http", "Hypertext Transfer Protocol"),
    110: ("pop3", "Post Office Protocol v3"),
    143: ("imap", "Internet Message Access Protocol"),
    443: ("https", "HTTP over TLS"),
    445: ("smb", "Server Message Block"),
    993: ("imaps", "IMAP over TLS"),
    995: ("pop3s", "POP3 over TLS"),
    1433: ("mssql", "Microsoft SQL Server"),
    1521: ("oracle", "Oracle Database"),
    2049: ("nfs", "Network File System"),
    3306: ("mysql", "MySQL Database"),
    3389: ("rdp", "Remote Desktop Protocol"),
    5432: ("postgresql", "PostgreSQL Database"),
    5900: ("vnc", "Virtual Network Computing"),
    6379: ("redis", "Redis"),
    8000: ("http-alt", "HTTP alternate"),
    8080: ("http-alt", "HTTP alternate"),
    8443: ("https-alt", "HTTPS alternate"),
    9200: ("elasticsearch", "Elasticsearch"),
    11211: ("memcached", "Memcached"),
    27017: ("mongodb", "MongoDB"),
}


def guess_service(port: int) -> tuple[str, str]:
    """Return a short service name and description for a TCP port."""
    return _PORT_SERVICE_MAP.get(port, ("unknown", "Unknown service"))


def guess_short(port: int) -> str:
    """Return the short service name for a TCP port."""
    name, _description = guess_service(port)
    return name
