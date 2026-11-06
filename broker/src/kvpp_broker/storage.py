from __future__ import annotations

import copy
import json
import threading
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from .errors import CompareFailed, CorruptState, InvalidRequest, StorageUnavailable


def canonical_json(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise InvalidRequest("The request must have a canonical JSON representation.") from exc


def strict_json(data):
    def object_hook(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON field")
            value[key] = item
        return value

    def invalid_constant(value):
        raise ValueError("Non-finite JSON value")
    return json.loads(data, object_pairs_hook=object_hook, parse_constant=invalid_constant)


@dataclass(frozen=True)
class Row:
    value: dict
    etag: str


class PartitionStore(Protocol):
    def read(self, partition: str, row: str) -> Row | None: ...

    def commit(self, partition: str, reads: dict[str, Row | None], writes: dict[str, dict]) -> None:
        """Atomically condition all writes on their read ETags and owner guard.

        Transport errors may mean committed. Never convert those to CompareFailed.
        """
        ...


def validate_commit(reads: dict[str, Row | None], writes: dict[str, dict]) -> None:
    if "owner" not in reads or "owner" not in writes or not 1 <= len(writes) <= 16:
        raise InvalidRequest("Every bounded transaction must condition and advance the owner guard.")
    if any(key not in reads for key in writes):
        raise InvalidRequest("Blind writes are forbidden.")
    old = reads["owner"].value if reads["owner"] else {"revision": 0, "epoch": 0}
    new = writes["owner"]
    if (type(new.get("schema")) is not int or new["schema"] != 1 or new.get("kind") != "owner" or
            type(new.get("revision")) is not int or type(new.get("epoch")) is not int or
            new["revision"] != old["revision"] + 1 or not old["epoch"] <= new["epoch"] <= old["epoch"] + 1):
        raise InvalidRequest("Owner revision must advance exactly once and its epoch cannot roll back.")
    for value in writes.values():
        if len(canonical_json(value)) > 16000:
            raise InvalidRequest("Broker row exceeds its bounded storage budget.")


class MemoryStore:
    """Deterministic test store; never a deployment persistence option."""

    def __init__(self):
        self._rows: dict[tuple[str, str], Row] = {}
        self._lock = threading.Lock()
        self._sequence = 0

    def read(self, partition: str, row: str) -> Row | None:
        with self._lock:
            return copy.deepcopy(self._rows.get((partition, row)))

    def commit(self, partition: str, reads: dict[str, Row | None], writes: dict[str, dict]) -> None:
        validate_commit(reads, writes)
        with self._lock:
            for key, expected in reads.items():
                actual = self._rows.get((partition, key))
                if (actual.etag if actual else None) != (expected.etag if expected else None):
                    raise CompareFailed()
            self._sequence += 1
            for key, value in writes.items():
                self._rows[partition, key] = Row(copy.deepcopy(value), str(self._sequence))


class AzureTableStore:
    """Same-partition ETag transactions. Provision the table outside this adapter.

    The broker identity must be the sole writer. A root ETag protects *all* reads,
    including rows read but not changed. SDK transport retries must be disabled.
    """

    def __init__(self, table_client):
        self.client = table_client

    @classmethod
    def from_endpoint(cls, endpoint: str, table_name: str, credential, *, allow_local_emulator: bool = False):
        from azure.data.tables import TableClient

        url = urlsplit(endpoint)
        if (not url.hostname or url.username or url.password or url.query or url.fragment or
                (url.scheme != "https" and not (allow_local_emulator and url.scheme == "http" and url.hostname == "127.0.0.1"))):
            raise InvalidRequest("Table storage requires HTTPS; only the explicit loopback emulator may use HTTP.")
        return cls(TableClient(endpoint, table_name, credential=credential, retry_total=0,
            connection_timeout=5, read_timeout=15))

    def read(self, partition: str, row: str) -> Row | None:
        from azure.core.exceptions import AzureError, ResourceNotFoundError

        try:
            entity = self.client.get_entity(partition_key=partition, row_key=row)
        except ResourceNotFoundError as exc:
            # A missing table is an outage/configuration error, not an empty owner.
            if exc.error_code == "ResourceNotFound":
                return None
            raise StorageUnavailable("Broker storage is unavailable.") from exc
        except AzureError as exc:
            raise StorageUnavailable("Broker storage is unavailable.") from exc
        try:
            payload = entity["Payload"]
            if not isinstance(payload, str) or len(payload) > 16000:
                raise ValueError()
            value = strict_json(payload)
            etag = entity.metadata["etag"]
            if not isinstance(value, dict) or not etag or etag == "*":
                raise ValueError()
            return Row(value, etag)
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            raise CorruptState("Stored broker row is malformed.") from exc

    def commit(self, partition: str, reads: dict[str, Row | None], writes: dict[str, dict]) -> None:
        from azure.core import MatchConditions
        from azure.core.exceptions import AzureError

        validate_commit(reads, writes)
        actions = []
        for key, value in writes.items():
            entity = {"PartitionKey": partition, "RowKey": key, "Payload": canonical_json(value)}
            expected = reads[key]
            if expected is None:
                actions.append(("create", entity))
            else:
                actions.append(("update", entity, {"mode": "replace", "etag": expected.etag,
                    "match_condition": MatchConditions.IfNotModified}))
        try:
            self.client.submit_transaction(actions)
        except AzureError as exc:
            if getattr(exc, "status_code", None) in (409, 412):
                raise CompareFailed() from exc
            # No automatic mutation retry after an ambiguous transport outcome.
            raise StorageUnavailable("Broker transaction outcome is unknown; retry the same request key.") from exc
