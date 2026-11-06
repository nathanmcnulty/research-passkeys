import concurrent.futures
import copy
import threading
import unittest

from kvpp_broker.coordination import AuthenticatedCaller, Coordinator, Transaction, MAX_COUNTER
from kvpp_broker.errors import Conflict, CorruptState, GateClosed, InvalidRequest, NotFound, StorageUnavailable, Unauthenticated
from kvpp_broker.storage import MemoryStore

TENANT = "11111111-1111-4111-8111-111111111111"
OWNER = "22222222-2222-4222-8222-222222222222"
APP = "33333333-3333-4333-8333-333333333333"
OTHER_OWNER = "44444444-4444-4444-8444-444444444444"
CREDENTIAL = "a" * 32


def caller(object_id=OWNER, expires_at=10000):
    return AuthenticatedCaller(TENANT, object_id, APP, expires_at)


def seed_active(store, principal, credential_id=CREDENTIAL, counter=0):
    # Storage fixture only. There is deliberately no activation API or test flag.
    tx = Transaction(store, principal.partition)
    tx.put(f"credential-{credential_id}", {"schema": 1, "kind": "credential", "credential_id": credential_id,
        "state": "active", "rp_id": "example.test", "counter": counter, "lease": None,
        "key_reference": "private-key-generation-one", "created_at": 1000})
    tx.commit()


class CoordinationCases:
    def make_store(self):
        return MemoryStore()

    def setUp(self):
        self.store = self.make_store()
        self.now = 1000
        self.caller = caller()
        self.api = Coordinator(self.store, frozenset([APP]), lambda: self.now)

    def seed(self, counter=0):
        seed_active(self.store, self.caller, counter=counter)

    def test_duplicate_reserve_has_one_durable_outcome(self):
        first = self.api.reserve(self.caller, "1" * 32, "example.test")
        self.assertEqual(first, Coordinator(self.store, frozenset([APP]), lambda: self.now).reserve(self.caller, "1" * 32, "example.test"))
        self.assertEqual(self.store.read(self.caller.partition, "owner").value["revision"], 1)

    def test_conflicting_payload_and_action_do_not_mutate(self):
        self.api.reserve(self.caller, "1" * 32, "example.test")
        root = self.store.read(self.caller.partition, "owner")
        with self.assertRaises(Conflict):
            self.api.reserve(self.caller, "1" * 32, "other.test")
        with self.assertRaises(Conflict):
            self.api.revoke(self.caller, "1" * 32)
        self.assertEqual(root, self.store.read(self.caller.partition, "owner"))

    def test_owner_isolation_and_same_key_namespace(self):
        first = self.api.reserve(self.caller, "1" * 32, "example.test")
        other = caller(OTHER_OWNER)
        with self.assertRaises(NotFound):
            self.api.get_credential(other, first["credential_id"])
        second = self.api.reserve(other, "1" * 32, "example.test")
        self.assertNotEqual(first["credential_id"], second["credential_id"])

    def test_abort_is_retained_and_old_request_cannot_resurrect(self):
        first = self.api.reserve(self.caller, "1" * 32, "example.test")
        self.api.abort(self.caller, "2" * 32, first["credential_id"])
        self.api.reserve(self.caller, "1" * 32, "example.test")
        self.assertEqual(self.api.get_credential(self.caller, first["credential_id"])["state"], "aborted")

    def test_expired_authentication_cannot_replay_cached_result(self):
        self.api.reserve(self.caller, "1" * 32, "example.test")
        with self.assertRaises(Unauthenticated):
            self.api.reserve(caller(expires_at=1000), "1" * 32, "example.test")
        with self.assertRaises(Unauthenticated):
            Coordinator(self.store, frozenset([OTHER_OWNER]), lambda: self.now).reserve(self.caller, "2" * 32, "example.test")

    def test_parallel_preparations_reserve_one_counter(self):
        self.seed(41)
        barrier = threading.Barrier(2)
        def prepare(key):
            barrier.wait(timeout=10)
            try:
                return self.api.prepare(self.caller, key * 32, CREDENTIAL, "example.test", "a" * 64)
            except Conflict:
                return None
        with concurrent.futures.ThreadPoolExecutor(2) as workers:
            results = list(workers.map(prepare, ["1", "2"]))
        self.assertEqual(sum(value is not None for value in results), 1)
        self.assertEqual(next(value for value in results if value)["counter"], 42)
        self.assertEqual(self.api.get_credential(self.caller, CREDENTIAL)["counter"], 42)

    def test_preparation_retry_preserves_nonce_counter_and_lease(self):
        self.seed()
        first = self.api.prepare(self.caller, "1" * 32, CREDENTIAL, "example.test", "a" * 64)
        self.assertEqual(first, self.api.prepare(self.caller, "1" * 32, CREDENTIAL, "example.test", "a" * 64))
        with self.assertRaises(Conflict):
            self.api.prepare(self.caller, "1" * 32, CREDENTIAL, "example.test", "b" * 64)
        self.assertEqual(self.api.get_credential(self.caller, CREDENTIAL)["counter"], 1)

    def test_expired_preparation_consumes_counter(self):
        self.seed()
        first = self.api.prepare(self.caller, "1" * 32, CREDENTIAL, "example.test", "a" * 64)
        self.now = first["expires_at"]
        second = self.api.prepare(self.caller, "2" * 32, CREDENTIAL, "example.test", "b" * 64)
        self.assertEqual(second["counter"], 2)
        self.assertEqual(self.store.read(self.caller.partition, f"operation-{first['operation_id']}").value["state"], "expired")

    def test_unknown_signing_is_never_reclaimed_by_lease_expiry(self):
        self.seed()
        first = self.api.prepare(self.caller, "1" * 32, CREDENTIAL, "example.test", "a" * 64)
        tx = Transaction(self.store, self.caller.partition)
        key = f"operation-{first['operation_id']}"
        tx.put(key, {**tx.require(key, "operation"), "state": "unknown"})
        tx.commit()
        self.now += 1000
        with self.assertRaises(Conflict):
            self.api.prepare(self.caller, "2" * 32, CREDENTIAL, "example.test", "a" * 64)
        self.assertEqual(self.api.get_credential(self.caller, CREDENTIAL)["counter"], 1)

    def test_counter_exhaustion_is_closed(self):
        self.seed(MAX_COUNTER)
        with self.assertRaises(Conflict):
            self.api.prepare(self.caller, "1" * 32, CREDENTIAL, "example.test", "a" * 64)

    def test_revocation_epoch_and_preparation_are_ordered(self):
        self.seed()
        self.assertEqual(self.api.revoke(self.caller, "1" * 32), {"epoch": 1})
        op = self.api.prepare(self.caller, "2" * 32, CREDENTIAL, "example.test", "a" * 64)
        self.assertEqual(self.store.read(self.caller.partition, f"operation-{op['operation_id']}").value["epoch"], 1)
        self.api.revoke(self.caller, "3" * 32)
        self.assertEqual(self.store.read(self.caller.partition, "owner").value["epoch"], 2)

    def test_malformed_inputs_do_not_create_storage(self):
        for rp in ["Example.test", "example.test/keys", "example..test", "-bad.test", "x" * 64 + ".test"]:
            with self.assertRaises(InvalidRequest):
                self.api.reserve(self.caller, "1" * 32, rp)
        self.assertIsNone(self.store.read(self.caller.partition, "owner"))

    def test_activation_and_signing_gates_have_no_storage_side_effect(self):
        for method in [self.api.finalize_registration, self.api.sign_assertion]:
            with self.assertRaises(GateClosed):
                method(userPresent=True, userVerified=True, pinVerified=True)
        self.assertIsNone(self.store.read(self.caller.partition, "owner"))


class MemoryCoordinationTests(CoordinationCases, unittest.TestCase):
    pass


class UnknownCommitTests(unittest.TestCase):
    def test_lost_commit_acknowledgement_is_not_retried_internally(self):
        class LostAck(MemoryStore):
            fail = True
            calls = 0
            def commit(self, *args):
                self.calls += 1
                super().commit(*args)
                if self.fail:
                    self.fail = False
                    raise StorageUnavailable("lost acknowledgement")
        store = LostAck()
        api = Coordinator(store, frozenset([APP]), lambda: 1000)
        with self.assertRaises(StorageUnavailable):
            api.reserve(caller(), "1" * 32, "example.test")
        self.assertEqual(store.calls, 1)
        first = api.reserve(caller(), "1" * 32, "example.test")
        self.assertEqual(store.calls, 1)
        self.assertEqual(api.get_credential(caller(), first["credential_id"])["state"], "reserved")


if __name__ == "__main__":
    unittest.main()
