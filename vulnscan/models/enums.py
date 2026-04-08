from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"  # CVSS >= 9.0
    HIGH = "high"  # CVSS 7.0-8.9
    MEDIUM = "medium"  # CVSS 4.0-6.9
    LOW = "low"  # CVSS < 4.0
    INFO = "info"  # informational


class VulnType(str, Enum):
    SQLI = "sql_injection"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    CORS = "cors_misconfiguration"
    OPEN_REDIRECT = "open_redirect"
    MISSING_HEADER = "missing_security_header"
    SSL_WEAK = "weak_ssl_tls"
    DIR_LISTING = "directory_listing"
    SENSITIVE_FILE = "sensitive_file_exposed"
    OPEN_PORT = "open_port"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
