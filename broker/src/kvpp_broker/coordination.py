from __future__ import annotations

import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from typing import Callable
from uuid import UUID

from .errors import CompareFailed, Conflict, CorruptState, GateClosed, InvalidRequest, NotFound, Unauthenticated
from .storage import PartitionStore, canonical_json

OPAQUE = re.compile(r"[0-9a-f]{32}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
RP = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
MAX_COUNTER = 2**32 - 1


def opaque(value: str) -> str:
    if not isinstance(value, str) or not OPAQUE.fullmatch(value):
        raise InvalidRequest("An opaque 128-bit identifier is required.")
    return value


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class AuthenticatedCaller:
    """Trusted server authentication result, NOT deserialized from an API body.

    An eventual API must verify Entra signature/issuer/audience/app/CA before
    constructing this context. This library is not itself an authentication API.
    """

    tenant_id: str
    object_id: str
    application_id: str
    expires_at: int

    def __post_init__(self):
        for name in ("tenant_id", "object_id", "application_id"):
            value = getattr(self, name)
            try:
                normalized = str(UUID(value))
            except (ValueError, TypeError, AttributeError) as exc:
                raise InvalidRequest("Caller identifiers must be UUIDs.") from exc
            if normalized != value:
                raise InvalidRequest("Caller identifiers must be canonical UUIDs.")
        if type(self.expires_at) is not int:
            raise InvalidRequest("Caller expiration must be an integer timestamp.")

    @property
    def partition(self) -> str:
        return hashlib.sha256(f"{self.tenant_id}:{self.object_id}".encode("ascii")).hexdigest()


class Transaction:
    def __init__(self, store: PartitionStore, partition: str):
        self.store, self.partition = store, partition
        self.reads, self.writes = {}, {}
        self.root = self.get("owner")
        if self.root is None:
            self.root = {"schema": 1, "kind": "owner", "revision": 0, "epoch": 0}
        if (self.root.get("schema") != 1 or self.root.get("kind") != "owner" or
                any(type(self.root.get(key)) is not int or self.root[key] < 0 for key in ("revision", "epoch"))):
            raise CorruptState("Owner guard is malformed.")

    def get(self, key: str) -> dict | None:
        if key not in self.reads:
            self.reads[key] = self.store.read(self.partition, key)
        row = self.reads[key]
        if row is not None and key != "owner" and self.reads["owner"] is None:
            raise CorruptState("Owner guard is missing for retained broker state.")
        return self.writes.get(key, row.value if row else None)

    def require(self, key: str, kind: str) -> dict:
        value = self.get(key)
        if value is None:
            raise NotFound("The resource was not found.")
        if value.get("kind") != kind or value.get("schema") != 1:
            raise CorruptState("Broker resource schema does not match its row.")
        return value

    def put(self, key: str, value: dict):
        self.get(key)
        self.writes[key] = value

    def commit(self):
        self.writes["owner"] = {**self.root, "revision": self.root["revision"] + 1}
        self.store.commit(self.partition, self.reads, self.writes)


class Coordinator:
    def __init__(self, store: PartitionStore, allowed_applications: frozenset[str], clock: Callable[[], int] = lambda: int(time.time())):
        if not allowed_applications:
            raise InvalidRequest("A broker application allowlist is required.")
        self.store, self.allowed_applications, self.clock = store, allowed_applications, clock

    def _authenticate(self, caller: AuthenticatedCaller) -> int:
        now = self.clock()
        if not isinstance(caller, AuthenticatedCaller) or caller.application_id not in self.allowed_applications or caller.expires_at <= now:
            raise Unauthenticated("Fresh broker authentication is required.")
        return now

    def _mutate(self, caller: AuthenticatedCaller, key: str, action: str, target: str, body: dict, change: Callable) -> dict:
        self._authenticate(caller)
        opaque(key)
        fingerprint = digest({"action": action, "target": target, "body": body, "application": caller.application_id})
        for _ in range(12):
            now = self._authenticate(caller)
            tx = Transaction(self.store, caller.partition)
            prior = tx.get(f"request-{key}")
            if prior:
                if prior.get("kind") != "request" or prior.get("schema") != 1:
                    raise CorruptState("Idempotency state is malformed.")
                if prior["fingerprint"] != fingerprint:
                    raise Conflict("Request key was already used for another operation.")
                self._authenticate(caller)
                return dict(prior["result"])
            result = change(tx, now)
            tx.put(f"request-{key}", {"schema": 1, "kind": "request", "fingerprint": fingerprint,
                "result": result, "created_at": now})
            try:
                # Authorization is checked again at the storage dispatch boundary.
                self._authenticate(caller)
                tx.commit()
                return dict(result)
            except CompareFailed:
                continue
        raise Conflict("Owner partition is busy; retry with the same request key.")

    def reserve(self, caller: AuthenticatedCaller, request_key: str, rp_id: str) -> dict:
        if not isinstance(rp_id, str) or not RP.fullmatch(rp_id) or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in rp_id.split(".")):
            raise InvalidRequest("A canonical RP ID is required.")

        def change(tx, now):
            credential_id = secrets.token_hex(16)
            result = {"credential_id": credential_id, "state": "reserved", "expires_at": now + 60}
            tx.put(f"credential-{credential_id}", {"schema": 1, "kind": "credential", **result,
                "rp_id": rp_id, "counter": 0, "lease": None, "key_reference": None, "created_at": now})
            return result
        return self._mutate(caller, request_key, "reserve", "", {"rp_id": rp_id}, change)

    def prepare(self, caller: AuthenticatedCaller, request_key: str, credential_id: str, rp_id: str, client_data_hash: str) -> dict:
        opaque(credential_id)
        if not isinstance(client_data_hash, str) or not DIGEST.fullmatch(client_data_hash):
            raise InvalidRequest("An exact clientDataJSON SHA-256 digest is required.")

        def change(tx, now):
            row = f"credential-{credential_id}"
            credential = tx.require(row, "credential")
            if credential["state"] != "active" or credential["rp_id"] != rp_id:
                raise Conflict("Credential cannot prepare this operation.")
            if credential["lease"]:
                old_row = f"operation-{credential['lease']}"
                old = tx.require(old_row, "operation")
                if old["state"] != "prepared" or old["expires_at"] > now:
                    raise Conflict("Credential already has an outstanding operation.")
                tx.put(old_row, {**old, "state": "expired"})
            counter = credential["counter"]
            if type(counter) is not int or not 0 <= counter <= MAX_COUNTER:
                raise CorruptState("Credential counter is malformed.")
            if counter == MAX_COUNTER:
                raise Conflict("Credential counter is exhausted.")
            operation_id = secrets.token_hex(16)
            result = {"operation_id": operation_id, "counter": counter + 1, "nonce": secrets.token_hex(32), "expires_at": now + 60}
            tx.put(f"operation-{operation_id}", {"schema": 1, "kind": "operation", **result,
                "credential_id": credential_id, "state": "prepared", "epoch": tx.root["epoch"],
                "request_hash": client_data_hash, "application_id": caller.application_id})
            tx.put(row, {**credential, "counter": counter + 1, "lease": operation_id})
            return result
        return self._mutate(caller, request_key, "prepare", credential_id,
            {"rp_id": rp_id, "client_data_hash": client_data_hash}, change)

    def abort(self, caller: AuthenticatedCaller, request_key: str, credential_id: str) -> dict:
        opaque(credential_id)

        def change(tx, now):
            row = f"credential-{credential_id}"
            credential = tx.require(row, "credential")
            if credential["state"] not in ("reserved", "aborted"):
                raise Conflict("An active credential requires deletion.")
            tx.put(row, {**credential, "state": "aborted", "terminal_at": now})
            return {"credential_id": credential_id, "state": "aborted"}
        return self._mutate(caller, request_key, "abort", credential_id, {}, change)

    def revoke(self, caller: AuthenticatedCaller, request_key: str) -> dict:
        def change(tx, now):
            tx.root = {**tx.root, "epoch": tx.root["epoch"] + 1}
            return {"epoch": tx.root["epoch"]}
        return self._mutate(caller, request_key, "revoke", "", {}, change)

    def get_credential(self, caller: AuthenticatedCaller, credential_id: str) -> dict:
        self._authenticate(caller)
        opaque(credential_id)
        value = Transaction(self.store, caller.partition).require(f"credential-{credential_id}", "credential")
        self._authenticate(caller)
        # Public projection never exposes key coordinates, lease secrets or claims.
        return {key: value[key] for key in ("credential_id", "state", "rp_id", "counter")}

    def finalize_registration(self, *args, **kwargs):
        raise GateClosed("Trusted create proof and RP acceptance integration are not implemented.")

    def sign_assertion(self, *args, **kwargs):
        raise GateClosed("Trusted proof, device and CA verification are not implemented.")
