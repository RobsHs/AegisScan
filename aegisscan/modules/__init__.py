"""
Audit and scanning modules for AegisScan.
"""

from aegisscan.modules.headers import audit_headers
from aegisscan.modules.cookies import audit_cookies
from aegisscan.modules.exposure import audit_exposure
from aegisscan.modules.tls_check import audit_tls
from aegisscan.modules.dns_mail import audit_dns_mail
from aegisscan.modules.cors import audit_cors

__all__ = [
    "audit_headers",
    "audit_cookies",
    "audit_exposure",
    "audit_tls",
    "audit_dns_mail",
    "audit_cors",
]
