import os
import multiprocessing
import unittest
from uuid import uuid4

from kvpp_broker.storage import AzureTableStore
from kvpp_broker.coordination import Coordinator
from kvpp_broker.errors import Conflict, CorruptState, StorageUnavailable
from test_coordination import APP, CREDENTIAL, CoordinationCases, caller


def emulator_store(table):
    from azure.core.credentials import AzureNamedKeyCredential
    return AzureTableStore.from_endpoint(os.environ["KVPP_TABLE_EMULATOR_ENDPOINT"], table,
        AzureNamedKeyCredential("brokerlocal", "Yg=="), allow_local_emulator=True)


def competing_process(table, gate, queue, action, key, cleanup_id):
    store = emulator_store(table)
    try:
        api = Coordinator(store, frozenset([APP]), lambda: 1000)
        queue.put(("ready",))
        if not gate.wait(20):
            raise RuntimeError("Competing processes did not start.")
        try:
            if action == "reserve":
                result = api.reserve(caller(), "f" * 32, "example.test")
            elif action == "prepare":
                result = api.prepare(caller(), key * 32, CREDENTIAL, "example.test", "a" * 64)
            elif action == "claim":
                result = api.claim_cleanup(caller(), key * 32, cleanup_id, key * 32)
            else:
                raise ValueError("Unknown test operation")
            queue.put(("ok", result))
        except Conflict:
            queue.put(("conflict",))
    finally:
        store.client.close()


@unittest.skipUnless(os.environ.get("KVPP_TABLE_EMULATOR_ENDPOINT"), "Run the local Azurite harness for real ETag transactions.")
class AzureTableCoordinationTests(CoordinationCases, unittest.TestCase):
    def make_store(self):
        store = emulator_store("Broker" + uuid4().hex)
        store.client.create_table()
        self.addCleanup(store.client.close)
        self.addCleanup(store.client.delete_table)
        return store

    def race_processes(self, action, cleanup_id=None):
        context = multiprocessing.get_context("spawn")
        gate, queue = context.Event(), context.Queue()
        processes = [context.Process(target=competing_process,
            args=(self.store.client.table_name, gate, queue, action, key, cleanup_id)) for key in ["b", "c"]]
        try:
            for process in processes:
                process.start()
            for _ in processes:
                self.assertEqual(queue.get(timeout=30), ("ready",))
            gate.set()
            results = [queue.get(timeout=30) for _ in processes]
            for process in processes:
                process.join(timeout=10)
                self.assertEqual(process.exitcode, 0)
            return results
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=10)
            queue.close()

    def test_separate_processes_share_one_idempotent_reservation(self):
        results = self.race_processes("reserve")
        self.assertTrue(all(result[0] == "ok" for result in results))
        self.assertEqual(results[0][1], results[1][1])
        self.assertEqual(self.store.read(self.caller.partition, "owner").value["revision"], 1)

    def test_separate_processes_allocate_only_one_counter(self):
        self.seed(41)
        results = self.race_processes("prepare")
        self.assertEqual(sorted(result[0] for result in results), ["conflict", "ok"])
        self.assertEqual(self.api.get_credential(self.caller, CREDENTIAL)["counter"], 42)

    def test_separate_processes_claim_only_one_cleanup(self):
        self.seed()
        cleanup_id = self.api.delete(self.caller, "1" * 32, CREDENTIAL)["cleanup_id"]
        results = self.race_processes("claim", cleanup_id)
        self.assertEqual(sorted(result[0] for result in results), ["conflict", "ok"])
        self.assertEqual(self.store.read(self.caller.partition, f"cleanup-{cleanup_id}").value["generation"], 1)

    def test_real_committed_transaction_with_lost_acknowledgement(self):
        from azure.core.exceptions import ServiceRequestError
        class LostAck:
            def submit_transaction(_, actions):
                self.store.client.submit_transaction(actions)
                raise ServiceRequestError("Synthetic loss after emulator commit")
            def get_entity(_, **kwargs):
                return self.store.client.get_entity(**kwargs)
        api = Coordinator(AzureTableStore(LostAck()), frozenset([APP]), lambda: 1000)
        with self.assertRaises(StorageUnavailable):
            api.reserve(self.caller, "1" * 32, "example.test")
        result = self.api.reserve(self.caller, "1" * 32, "example.test")
        self.assertEqual(self.api.get_credential(self.caller, result["credential_id"])["state"], "reserved")
        self.assertEqual(self.store.read(self.caller.partition, "owner").value["revision"], 1)

    def test_missing_table_is_not_an_empty_owner(self):
        store = emulator_store("Absent" + uuid4().hex)
        self.addCleanup(store.client.close)
        with self.assertRaises(StorageUnavailable):
            store.read(self.caller.partition, "owner")

    def test_malformed_payload_cannot_look_like_missing_state(self):
        self.store.client.create_entity({"PartitionKey": self.caller.partition, "RowKey": "owner", "Payload": "null"})
        with self.assertRaises(CorruptState):
            self.api.reserve(self.caller, "1" * 32, "example.test")


if __name__ == "__main__":
    unittest.main()
