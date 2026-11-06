import os
import multiprocessing
import concurrent.futures
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

    def test_duplicate_non_finite_or_oversized_stored_json_fails_closed(self):
        for payload in ['{"schema":1,"kind":"owner","revision":1,"epoch":0,"epoch":1}',
                '{"schema":1,"kind":"owner","revision":1,"epoch":NaN}', '{"noise":"' + "x" * 16001 + '"}']:
            self.store.client.upsert_entity({"PartitionKey": self.caller.partition, "RowKey": "owner", "Payload": payload}, mode="replace")
            with self.assertRaises(CorruptState):
                self.api.reserve(self.caller, "1" * 32, "example.test")

    def test_missing_guard_does_not_reinitialize_a_retained_request(self):
        self.api.reserve(self.caller, "1" * 32, "example.test")
        self.store.client.delete_entity(partition_key=self.caller.partition, row_key="owner")
        with self.assertRaises(CorruptState):
            self.api.reserve(self.caller, "1" * 32, "example.test")
        self.assertIsNone(self.store.read(self.caller.partition, "owner"))

    def test_signed_http_clients_recover_one_reservation_after_lost_success(self):
        import requests
        from kvpp_broker.api import BrokerApplication
        from auth_fixtures import token, verifier
        from api_http_fixture import api_server
        app = BrokerApplication(Coordinator(self.store, frozenset([APP])), verifier())
        # The gateway loses the first success *after* the real authenticated API
        # transaction commits. An exact client retry must recover the same result.
        dropped = []
        committed = []
        def gateway(environ, start_response):
            if not dropped:
                dropped.append(True)
                result = b"".join(app(environ, lambda *args: None))
                committed.append(result)
                start_response("503 Service Unavailable", [("Content-Type", "application/json"), ("Cache-Control", "no-store")])
                return [b'{"error":"synthetic lost success"}']
            return app(environ, start_response)
        with api_server(gateway) as url, requests.Session() as first, requests.Session() as second:
            first.trust_env = second.trust_env = False
            headers = {"Authorization": "Bearer " + token(), "Idempotency-Key": "f" * 32}
            self.assertEqual(first.post(url + "/v1/reservations", headers=headers, json={"rpId": "example.test"}, timeout=10).status_code, 503)
            recovered = second.post(url + "/v1/reservations", headers=headers, json={"rpId": "example.test"}, timeout=10)
            self.assertEqual(recovered.status_code, 201)
            import json
            self.assertEqual(recovered.json(), json.loads(committed[0]))
            self.assertEqual(self.store.read(self.caller.partition, "owner").value["revision"], 1)

    def test_signed_http_clients_race_one_counter_without_signing(self):
        import requests
        from kvpp_broker.api import BrokerApplication
        from auth_fixtures import token, verifier
        from api_http_fixture import api_server
        self.seed(41)
        app = BrokerApplication(Coordinator(self.store, frozenset([APP])), verifier())
        authorization = "Bearer " + token()
        with api_server(app) as url:
            def prepare(key):
                with requests.Session() as client:
                    client.trust_env = False
                    response = client.post(url + f"/v1/credentials/{CREDENTIAL}/prepare",
                        headers={"Authorization": authorization, "Idempotency-Key": key * 32},
                        json={"rpId": "example.test", "clientDataHash": "a" * 64}, timeout=10)
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    return response.status_code, response.json()
            with concurrent.futures.ThreadPoolExecutor(2) as workers:
                results = list(workers.map(prepare, ["1", "2"]))
            self.assertEqual(sorted(status for status, _ in results), [200, 409])
            winner = next(value for status, value in results if status == 200)
            self.assertEqual(winner["counter"], 42)
            self.assertNotIn("signature", winner)
            self.assertEqual(self.api.get_credential(self.caller, CREDENTIAL)["counter"], 42)

    def test_http_step_up_precedes_reservation_and_does_not_bypass_replay_policy(self):
        import requests
        from kvpp_broker.api import BrokerApplication
        from auth_fixtures import payload, token, verifier
        from api_http_fixture import api_server
        app = BrokerApplication(Coordinator(self.store, frozenset([APP])), verifier())
        with api_server(app) as url, requests.Session() as client:
            client.trust_env = False
            headers = {"Authorization": "Bearer " + token(payload(acrs=[])), "Idempotency-Key": "1" * 32}
            response = client.post(url + "/v1/reservations", headers=headers, json={"rpId": "example.test"}, timeout=10)
            self.assertEqual(response.status_code, 401)
            self.assertIn('error="insufficient_claims"', response.headers["WWW-Authenticate"])
            self.assertIsNone(self.store.read(self.caller.partition, "owner"))
            headers["Authorization"] = "Bearer " + token()
            self.assertEqual(client.post(url + "/v1/reservations", headers=headers, json={"rpId": "example.test"}, timeout=10).status_code, 201)
            self.assertEqual(self.store.read(self.caller.partition, "owner").value["revision"], 1)


if __name__ == "__main__":
    unittest.main()
