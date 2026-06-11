"""Core utilities for DNS Scanner Pro.

This module intentionally contains no GUI code. Keeping the scan logic separate
makes the project easier to test, maintain and extend.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Iterable, List, Sequence
from urllib.parse import urlparse

try:
    import dns.exception
    import dns.resolver

    DNSPYTHON_AVAILABLE = True
except ImportError:  # pragma: no cover - fallback for minimal environments
    DNSPYTHON_AVAILABLE = False


LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
SUPPORTED_RECORDS = ("A", "AAAA", "CNAME")


@dataclass(frozen=True)
class ScannerConfig:
    """Runtime configuration for a DNS scan."""

    max_threads: int = 20
    timeout: float = 3.0
    retries: int = 1
    record_types: Sequence[str] = field(default_factory=lambda: ("A",))

    def __post_init__(self) -> None:
        if not 1 <= int(self.max_threads) <= 100:
            raise ValueError("max_threads must be between 1 and 100")
        if float(self.timeout) <= 0:
            raise ValueError("timeout must be greater than zero")
        if int(self.retries) < 0:
            raise ValueError("retries cannot be negative")
        invalid_records = [r for r in self.record_types if r.upper() not in SUPPORTED_RECORDS]
        if invalid_records:
            raise ValueError(f"Unsupported DNS record types: {', '.join(invalid_records)}")


@dataclass(frozen=True)
class DNSRecord:
    record_type: str
    value: str


@dataclass(frozen=True)
class ScanResult:
    hostname: str
    records: List[DNSRecord]

    def to_display_line(self) -> str:
        values = ", ".join(f"{record.record_type}:{record.value}" for record in self.records)
        return f"[FOUND] {self.hostname} -> {values}"


def normalize_domain(raw_domain: str) -> str:
    """Normalize user input into a bare domain name.

    Accepts values such as:
    - example.com
    - https://example.com/login
    - http://sub.example.com:8080/path
    """

    value = (raw_domain or "").strip().lower()
    if not value:
        raise ValueError("Informe um domínio.")

    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
    else:
        # urlparse('example.com/path') treats the whole string as path, so the
        # double slash forces netloc parsing without requiring a scheme.
        parsed = urlparse(f"//{value}")
        host = parsed.hostname or value.split("/")[0].split(":")[0]

    domain = host.strip().strip(".")

    if not is_valid_domain(domain):
        raise ValueError(
            "Domínio inválido. Use um domínio como exemplo.com, sem espaços ou caracteres especiais."
        )
    return domain


def is_valid_domain(domain: str) -> bool:
    domain = (domain or "").strip().strip(".").lower()
    if len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    return all(LABEL_RE.match(label) for label in labels)


def is_valid_wordlist_entry(entry: str) -> bool:
    entry = (entry or "").strip().strip(".").lower()
    if not entry or len(entry) > 253:
        return False
    return all(LABEL_RE.match(label) for label in entry.split("."))


def clean_wordlist(lines: Iterable[str]) -> List[str]:
    """Remove empty lines, comments, duplicates and invalid DNS labels."""

    cleaned: List[str] = []
    seen = set()

    for raw in lines:
        value = raw.strip().lower()
        if not value or value.startswith("#"):
            continue
        # Allow inline comments: admin  # painel administrativo
        value = value.split("#", 1)[0].strip().strip(".")
        if not value or not is_valid_wordlist_entry(value):
            continue
        if value not in seen:
            seen.add(value)
            cleaned.append(value)

    return cleaned


class DNSResolver:
    """DNS resolver wrapper with dnspython support and stdlib fallback."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.record_types = tuple(record.upper() for record in config.record_types)

        if DNSPYTHON_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = config.timeout
            self.resolver.lifetime = config.timeout
        else:
            self.resolver = None
            socket.setdefaulttimeout(config.timeout)

    def resolve(self, hostname: str) -> ScanResult | None:
        records: List[DNSRecord] = []

        for attempt in range(self.config.retries + 1):
            records = self._resolve_once(hostname)
            if records:
                return ScanResult(hostname=hostname, records=records)
            if attempt >= self.config.retries:
                break

        return None

    def _resolve_once(self, hostname: str) -> List[DNSRecord]:
        if DNSPYTHON_AVAILABLE:
            return self._resolve_with_dnspython(hostname)
        return self._resolve_with_socket(hostname)

    def _resolve_with_dnspython(self, hostname: str) -> List[DNSRecord]:
        records: List[DNSRecord] = []

        for record_type in self.record_types:
            try:
                answers = self.resolver.resolve(hostname, record_type)  # type: ignore[union-attr]
                for answer in answers:
                    records.append(DNSRecord(record_type=record_type, value=answer.to_text().rstrip(".")))
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                continue
            except Exception:
                continue

        return records

    def _resolve_with_socket(self, hostname: str) -> List[DNSRecord]:
        # stdlib fallback only supports IPv4 A-like resolution reliably.
        if "A" not in self.record_types:
            return []
        try:
            _, _, ips = socket.gethostbyname_ex(hostname)
            return [DNSRecord(record_type="A", value=ip) for ip in sorted(set(ips))]
        except (socket.gaierror, TimeoutError, OSError):
            return []


def build_hostname(prefix: str, domain: str) -> str:
    prefix = prefix.strip().strip(".").lower()
    domain = normalize_domain(domain)
    if not is_valid_wordlist_entry(prefix):
        raise ValueError(f"Subdomínio inválido na wordlist: {prefix}")
    return f"{prefix}.{domain}"
