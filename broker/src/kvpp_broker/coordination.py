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

    The preliminary WSGI boundary verifies tokens and configured authentication
    context through auth.EntraTokenVerifier. Native/device/ceremony policy is a
    separate gate and must never be inferred from this identity context.
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
            # Another worker can initialize owner+request atomically between our
            # two GETs. Retry that stale snapshot instead of declaring corruption.
            if self.store.read(self.partition, "owner") is not None:
                raise CompareFailed()
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

    def assert_current(self):
        expected = self.reads["owner"]
        actual = self.store.read(self.partition, "owner")
        if (actual.etag if actual else None) != (expected.etag if expected else None):
            raise CompareFailed()


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

    def _mutate(self, caller: AuthenticatedCaller, key: str, action: str, target: str, body: dict, change: Callable, *, replay_result: bool = True) -> dict:
        self._authenticate(caller)
        opaque(key)
        fingerprint = digest({"action": action, "target": target, "body": body, "application": caller.application_id})
        for _ in range(12):
            try:
                return self._attempt(caller, key, action, target, fingerprint, change, replay_result)
            except CompareFailed:
                continue
        raise Conflict("Owner partition is busy; retry with the same request key.")

    def _attempt(self, caller, key, action, target, fingerprint, change, replay_result):
        now = self._authenticate(caller)
        tx = Transaction(self.store, caller.partition)
        try:
            return self._apply(tx, caller, key, action, target, fingerprint, change, replay_result, now)
        except (Conflict, CorruptState, NotFound):
            # A dependent GET may observe a newer committed revision than the
            # first guard GET. Revalidate before treating it as a real denial or
            # corruption; writes themselves are protected by the transaction CAS.
            tx.assert_current()
            raise

    def _apply(self, tx, caller, key, action, target, fingerprint, change, replay_result, now):
        prior = tx.get(f"request-{key}")
        if prior:
            if prior.get("kind") != "request" or prior.get("schema") != 1:
                raise CorruptState("Idempotency state is malformed.")
            if prior["fingerprint"] != fingerprint:
                raise Conflict("Request key was already used for another operation.")
            self._authenticate(caller)
            if not replay_result:
                raise Conflict("Dispatch was already committed; its outcome requires reconciliation.")
            return dict(prior["result"])
        result = change(tx, now)
        tx.put(f"request-{key}", {"schema": 1, "kind": "request", "fingerprint": fingerprint,
            "result": result, "created_at": now})
        tx.put(f"audit-{key}", {"schema": 1, "kind": "audit", "action": action, "target_id": target,
            "revision": tx.root["revision"] + 1, "epoch": tx.root["epoch"], "created_at": now})
        # Authorization is checked again at the storage dispatch boundary.
        self._authenticate(caller)
        tx.commit()
        return dict(result)

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
                if type(old["epoch"]) is not int or not 0 <= old["epoch"] <= tx.root["epoch"]:
                    raise CorruptState("Operation authorization epoch is malformed or rolled back.")
                if old["credential_id"] != credential_id:
                    raise CorruptState("Credential lease belongs to another operation.")
                if old["state"] != "prepared" or (old["expires_at"] > now and old["epoch"] == tx.root["epoch"]):
                    raise Conflict("Credential already has an outstanding operation.")
                tx.put(old_row, {**old, "state": "revoked" if old["epoch"] != tx.root["epoch"] else "expired"})
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

    def delete(self, caller: AuthenticatedCaller, request_key: str, credential_id: str) -> dict:
        opaque(credential_id)

        def change(tx, now):
            row = f"credential-{credential_id}"
            credential = tx.require(row, "credential")
            if credential["state"] == "deleted":
                cleanup = tx.require(f"cleanup-{credential['cleanup_id']}", "cleanup")
                return {"credential_id": credential_id, "state": "deleted", "cleanup_id": cleanup["cleanup_id"]}
            if credential["state"] not in ("active", "disabled"):
                raise Conflict("Only an active or disabled credential can be deleted.")
            key_reference = credential["key_reference"]
            if not isinstance(key_reference, str) or not 1 <= len(key_reference) <= 512:
                raise CorruptState("Credential key identity is missing or malformed.")
            blocked = False
            if credential["lease"]:
                operation_row = f"operation-{credential['lease']}"
                operation = tx.require(operation_row, "operation")
                if operation["credential_id"] != credential_id:
                    raise CorruptState("Credential lease belongs to another operation.")
                if operation["state"] in ("signing", "unknown"):
                    blocked = True
                elif operation["state"] == "prepared":
                    tx.put(operation_row, {**operation, "state": "cancelled", "terminal_at": now})
                else:
                    raise CorruptState("Credential retained an unexpected operation lease.")
            cleanup_id = secrets.token_hex(16)
            tx.put(f"cleanup-{cleanup_id}", {"schema": 1, "kind": "cleanup", "cleanup_id": cleanup_id,
                "credential_id": credential_id, "key_reference": key_reference, "created_at": now,
                "state": "blocked" if blocked else "pending", "generation": 0, "worker_id": None,
                "claim_token": None, "claim_until": None, "dispatch_id": None})
            tx.put(row, {**credential, "state": "deleted", "terminal_at": now, "cleanup_id": cleanup_id,
                "lease": credential["lease"] if blocked else None})
            return {"credential_id": credential_id, "state": "deleted", "cleanup_id": cleanup_id}
        return self._mutate(caller, request_key, "delete", credential_id, {}, change)

    def claim_cleanup(self, caller: AuthenticatedCaller, request_key: str, cleanup_id: str, worker_id: str) -> dict:
        """Internal worker operation. This does not grant a Key Vault dispatch."""
        opaque(cleanup_id)
        opaque(worker_id)

        def change(tx, now):
            row = f"cleanup-{cleanup_id}"
            cleanup = tx.require(row, "cleanup")
            if cleanup["state"] != "pending" and not (cleanup["state"] == "claimed" and cleanup["claim_until"] <= now):
                raise Conflict("Cleanup is already claimed, blocked or has an unknown dispatched outcome.")
            result = {"cleanup_id": cleanup_id, "generation": cleanup["generation"] + 1,
                "claim_token": secrets.token_hex(16), "claim_until": now + 30}
            tx.put(row, {**cleanup, **result, "state": "claimed", "worker_id": worker_id})
            return result
        return self._mutate(caller, request_key, "claim-cleanup", cleanup_id, {"worker_id": worker_id}, change)

    def begin_cleanup(self, caller: AuthenticatedCaller, request_key: str, cleanup_id: str, worker_id: str, claim_token: str) -> dict:
        """Issue one internal dispatch ticket. A committed ticket is NEVER replayed.

        There is no remote deletion adapter yet. A future trusted adapter may use
        a returned ticket once, and must reconcile all ambiguous outcomes. Lease
        expiry cannot make a non-fenceable Key Vault request safe to dispatch twice.
        """
        opaque(cleanup_id)
        opaque(worker_id)
        opaque(claim_token)

        def change(tx, now):
            row = f"cleanup-{cleanup_id}"
            cleanup = tx.require(row, "cleanup")
            if (cleanup["state"] != "claimed" or cleanup["worker_id"] != worker_id or
                    cleanup["claim_until"] <= now or not secrets.compare_digest(cleanup["claim_token"], claim_token)):
                raise Conflict("Cleanup claim is stale or already dispatched.")
            credential = tx.require(f"credential-{cleanup['credential_id']}", "credential")
            if (credential["state"] != "deleted" or credential["cleanup_id"] != cleanup_id or
                    credential["key_reference"] != cleanup["key_reference"] or credential["lease"]):
                raise Conflict("Cleanup target identity or lifecycle no longer matches its tombstone.")
            dispatch_id = secrets.token_hex(16)
            tx.put(row, {**cleanup, "state": "dispatched", "dispatch_id": dispatch_id, "dispatched_at": now})
            return {"cleanup_id": cleanup_id, "dispatch_id": dispatch_id, "key_reference": cleanup["key_reference"]}
        return self._mutate(caller, request_key, "begin-cleanup", cleanup_id,
            {"worker_id": worker_id, "claim_token": claim_token}, change, replay_result=False)

    def mark_cleanup_unknown(self, caller: AuthenticatedCaller, request_key: str, cleanup_id: str, dispatch_id: str) -> dict:
        opaque(cleanup_id)
        opaque(dispatch_id)

        def change(tx, now):
            row = f"cleanup-{cleanup_id}"
            cleanup = tx.require(row, "cleanup")
            if cleanup["state"] not in ("dispatched", "unknown") or cleanup["dispatch_id"] != dispatch_id:
                raise Conflict("Cleanup dispatch identity does not match.")
            tx.put(row, {**cleanup, "state": "unknown", "unknown_at": now})
            return {"cleanup_id": cleanup_id, "state": "unknown"}
        return self._mutate(caller, request_key, "unknown-cleanup", cleanup_id, {"dispatch_id": dispatch_id}, change)

    def complete_cleanup(self, *args, **kwargs):
        raise GateClosed("A trusted exact-key reconciliation adapter is not implemented.")

    def get_credential(self, caller: AuthenticatedCaller, credential_id: str) -> dict:
        self._authenticate(caller)
        opaque(credential_id)
        for _ in range(12):
            try:
                tx = Transaction(self.store, caller.partition)
                value = tx.require(f"credential-{credential_id}", "credential")
                tx.assert_current()
                self._authenticate(caller)
                # Public projection never exposes key coordinates, lease secrets or claims.
                return {key: value[key] for key in ("credential_id", "state", "rp_id", "counter")}
            except CompareFailed:
                continue
        raise Conflict("Owner partition is busy; retry the read.")

    def finalize_registration(self, *args, **kwargs):
        raise GateClosed("Trusted create proof and RP acceptance integration are not implemented.")

    def sign_assertion(self, *args, **kwargs):
        raise GateClosed("Trusted proof, device and CA verification are not implemented.")
