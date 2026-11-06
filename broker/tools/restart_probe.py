"""Two separate broker processes with a full disk-backed emulator restart between."""
import json
import os
from pathlib import Path
import sys
import unittest
from uuid import uuid4

from azure.core.credentials import AzureNamedKeyCredential
from kvpp_broker.coordination import AuthenticatedCaller, Coordinator, Transaction
from kvpp_broker.errors import Conflict
from kvpp_broker.storage import AzureTableStore

APP = "33333333-3333-4333-8333-333333333333"
CALLER = AuthenticatedCaller("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", APP, 10000)
CREDENTIAL = "a" * 32


def main():
    phase, filename = sys.argv[1:]
    table = "Restart" + uuid4().hex if phase == "prepare" else json.loads(Path(filename).read_text())["table"]
    store = AzureTableStore.from_endpoint(os.environ["KVPP_TABLE_EMULATOR_ENDPOINT"], table,
        AzureNamedKeyCredential("brokerlocal", "Yg=="), allow_local_emulator=True)
    api = Coordinator(store, frozenset([APP]), lambda: 1000 if phase == "prepare" else 2000)
    check = unittest.TestCase()
    try:
        if phase == "prepare":
            store.client.create_table()
            reserved = api.reserve(CALLER, "1" * 32, "example.test")
            tx = Transaction(store, CALLER.partition)
            tx.put("credential-" + CREDENTIAL, {"schema": 1, "kind": "credential", "credential_id": CREDENTIAL,
                "state": "active", "rp_id": "example.test", "counter": 7, "lease": None,
                "key_reference": "private-fixture-key-generation", "created_at": 1000})
            tx.commit()
            api.prepare(CALLER, "2" * 32, CREDENTIAL, "example.test", "a" * 64)
            cleanup_id = api.delete(CALLER, "3" * 32, CREDENTIAL)["cleanup_id"]
            claim = api.claim_cleanup(CALLER, "4" * 32, cleanup_id, "a" * 32)
            ticket = api.begin_cleanup(CALLER, "5" * 32, cleanup_id, "a" * 32, claim["claim_token"])
            api.mark_cleanup_unknown(CALLER, "6" * 32, cleanup_id, ticket["dispatch_id"])
            Path(filename).write_text(json.dumps({"table": table, "reserved": reserved,
                "cleanup_id": cleanup_id, "claim_token": claim["claim_token"]}), encoding="utf-8")
        else:
            fixture = json.loads(Path(filename).read_text(encoding="utf-8"))
            check.assertEqual(api.reserve(CALLER, "1" * 32, "example.test"), fixture["reserved"])
            check.assertEqual(api.get_credential(CALLER, CREDENTIAL)["state"], "deleted")
            check.assertEqual(api.get_credential(CALLER, CREDENTIAL)["counter"], 8)
            with check.assertRaises(Conflict):
                api.begin_cleanup(CALLER, "5" * 32, fixture["cleanup_id"], "a" * 32, fixture["claim_token"])
            with check.assertRaises(Conflict):
                api.claim_cleanup(CALLER, "7" * 32, fixture["cleanup_id"], "b" * 32)
            with check.assertRaises(Conflict):
                api.prepare(CALLER, "8" * 32, CREDENTIAL, "example.test", "b" * 64)
            check.assertEqual(store.read(CALLER.partition, f"cleanup-{fixture['cleanup_id']}").value["state"], "unknown")
            store.client.delete_table()
            print(json.dumps({"validator": "broker-storage-restart", "diskRestart": True,
                "counter": 8, "tombstoneRetained": True, "idempotentResultRetained": True,
                "unknownDispatchNotReissued": True}))
    finally:
        store.client.close()


if __name__ == "__main__":
    main()
