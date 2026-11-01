"""certpeek — inspect the TLS certificate a host serves.

Point it at a host and it tells you what certificate is on the other end: who
it's for, who signed it, when it expires, whether the chain and hostname check
out, and the TLS version negotiated — including certificates that *don't*
validate, which are the ones you most want to see.

    >>> from certpeek import inspect
    >>> r = inspect("example.com")
    >>> r.days_left, r.issuer_cn, r.protocol
    (83, 'R3', 'TLSv1.3')
    >>> r.flags
    []

Pure standard library.
"""

from .inspect import Report, inspect, split_target

__version__ = "0.1.0"

__all__ = ["inspect", "Report", "split_target", "__version__"]
