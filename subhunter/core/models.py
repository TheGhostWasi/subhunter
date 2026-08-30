"""
Core data structures shared across the pipeline.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DNSInfo:
    a: list = field(default_factory=list)
    aaaa: list = field(default_factory=list)
    cname: Optional[str] = None
    mx: list = field(default_factory=list)
    ns: list = field(default_factory=list)
    txt: list = field(default_factory=list)
    error: Optional[str] = None  # e.g. "NXDOMAIN", "TIMEOUT", "SERVFAIL", "NoAnswer"

    @property
    def resolved(self):
        return bool(self.a or self.aaaa or self.cname)


@dataclass
class HTTPInfo:
    scheme: Optional[str] = None
    status: Optional[int] = None
    final_url: Optional[str] = None
    redirect_location: Optional[str] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    response_time_ms: Optional[float] = None
    technologies: list = field(default_factory=list)
    cdn_waf: list = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class IPInfo:
    ip: str
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None


@dataclass
class Host:
    host: str
    sources: set = field(default_factory=set)
    dns: Optional[DNSInfo] = None
    http: Optional[HTTPInfo] = None
    ip_info: list = field(default_factory=list)  # list[IPInfo]
    in_scope: bool = True
    excluded: bool = False

    def add_source(self, name):
        self.sources.add(name)

    def to_dict(self):
        d = {
            "host": self.host,
            "sources": sorted(self.sources),
        }
        if self.dns:
            d["dns"] = {
                "a": self.dns.a,
                "aaaa": self.dns.aaaa,
                "cname": self.dns.cname,
                "ns": self.dns.ns,
                "mx": self.dns.mx,
                "txt": self.dns.txt,
                "error": self.dns.error,
            }
        if self.http:
            d["http"] = {
                "status": self.http.status,
                "final_url": self.http.final_url,
                "redirect_location": self.http.redirect_location,
                "title": self.http.title,
                "server": self.http.server,
                "content_type": self.http.content_type,
                "content_length": self.http.content_length,
                "response_time_ms": self.http.response_time_ms,
                "technologies": self.http.technologies,
                "cdn_waf": self.http.cdn_waf,
                "error": self.http.error,
            }
        if self.ip_info:
            d["ip_info"] = [
                {"ip": i.ip, "asn": i.asn, "org": i.org, "country": i.country} for i in self.ip_info
            ]
        d["in_scope"] = self.in_scope
        d["excluded"] = self.excluded
        return d
