from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class InMemoryStore:
    ca_private_key_pem: str | None = None
    ca_certificate_pem: str | None = None
    certificates: dict[str, str] = field(default_factory=dict)
    signing_public_keys: dict[str, str] = field(default_factory=dict)
    agreement_public_keys: dict[str, str] = field(default_factory=dict)
    revoked: set[str] = field(default_factory=set)
    group_versions: dict[str, int] = field(default_factory=dict)
    group_keys_raw: dict[tuple[str, int], bytes] = field(default_factory=dict)
    wrapped_keys: dict[tuple[str, int, str], str] = field(default_factory=dict)


STORE = InMemoryStore()
