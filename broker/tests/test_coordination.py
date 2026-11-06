import concurrent.futures
import threading
import unittest

from kvpp_broker.coordination import AuthenticatedCaller, Coordinator, Transaction, MAX_COUNTER
from kvpp_broker.errors import CompareFailed, Conflict, CorruptState, GateClosed, InvalidRequest, NotFound, StorageUnavailable, Unauthenticated
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
        audit = self.store.read(self.caller.partition, "audit-" + "1" * 32).value
        self.assertEqual(audit["action"], "reserve")
        self.assertEqual(audit["revision"], 1)
        self.assertNotIn("rp_id", audit)
        self.assertNotIn("result", audit)

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
        next_op = self.api.prepare(self.caller, "4" * 32, CREDENTIAL, "example.test", "b" * 64)
        self.assertEqual(next_op["counter"], 2)
        self.assertEqual(self.store.read(self.caller.partition, f"operation-{op['operation_id']}").value["state"], "revoked")
        self.assertEqual(self.store.read(self.caller.partition, f"operation-{next_op['operation_id']}").value["epoch"], 2)

    def test_malformed_inputs_do_not_create_storage(self):
        for rp in ["Example.test", "example.test/keys", "example..test", "-bad.test", "x" * 64 + ".test"]:
            with self.assertRaises(InvalidRequest):
                self.api.reserve(self.caller, "1" * 32, rp)
        self.assertIsNone(self.store.read(self.caller.partition, "owner"))

    def test_activation_and_signing_gates_have_no_storage_side_effect(self):
        for method in [self.api.finalize_registration, self.api.sign_assertion, self.api.complete_cleanup]:
            with self.assertRaises(GateClosed):
                method(userPresent=True, userVerified=True, pinVerified=True)
        self.assertIsNone(self.store.read(self.caller.partition, "owner"))

    def test_stale_transaction_rolls_back_every_row(self):
        self.seed()
        stale = Transaction(self.store, self.caller.partition)
        stale.put("request-" + "f" * 32, {"kind": "fixture", "schema": 1})
        self.api.revoke(self.caller, "1" * 32)
        with self.assertRaises(CompareFailed):
            stale.commit()
        self.assertIsNone(self.store.read(self.caller.partition, "request-" + "f" * 32))
        self.assertEqual(self.store.read(self.caller.partition, "owner").value["epoch"], 1)

    def test_storage_boundary_rejects_guard_rollback(self):
        self.seed()
        self.api.revoke(self.caller, "1" * 32)
        original = self.store.read(self.caller.partition, "owner")
        for invalid in [{"epoch": 0}, {"revision": 0}, {"epoch": True}, {"schema": True}]:
            tx = Transaction(self.store, self.caller.partition)
            tx.root = {**tx.root, **invalid}
            with self.assertRaises(InvalidRequest):
                tx.commit()
            self.assertEqual(original, self.store.read(self.caller.partition, "owner"))

    def test_corrupt_record_identity_cannot_be_read_prepared_or_deleted(self):
        self.seed()
        row = "credential-" + CREDENTIAL
        tx = Transaction(self.store, self.caller.partition)
        tx.put(row, {**tx.get(row), "credential_id": "b" * 32})
        tx.commit()
        original = self.store.read(self.caller.partition, "owner")
        for operation in [lambda: self.api.get_credential(self.caller, CREDENTIAL),
                lambda: self.api.prepare(self.caller, "1" * 32, CREDENTIAL, "example.test", "a" * 64),
                lambda: self.api.delete(self.caller, "2" * 32, CREDENTIAL)]:
            with self.assertRaises(CorruptState):
                operation()
        self.assertEqual(original, self.store.read(self.caller.partition, "owner"))

    def test_corrupt_public_fields_fail_before_projection(self):
        self.seed()
        row = "credential-" + CREDENTIAL
        original = self.store.read(self.caller.partition, row).value
        for overrides in [{"counter": {"private": "internal-value"}}, {"counter": True}, {"counter": MAX_COUNTER + 1},
                {"rp_id": {"private": "internal-value"}}, {"state": "unexpected"}, {"key_reference": None}, {"schema": True}]:
            tx = Transaction(self.store, self.caller.partition)
            tx.put(row, {**original, **overrides})
            tx.commit()
            with self.assertRaises(CorruptState):
                self.api.get_credential(self.caller, CREDENTIAL)

    def test_request_key_cannot_replay_across_allowed_applications(self):
        self.api.reserve(self.caller, "1" * 32, "example.test")
        api = Coordinator(self.store, frozenset([APP, OTHER_OWNER]), lambda: self.now)
        other_app = AuthenticatedCaller(TENANT, OWNER, OTHER_OWNER, 10000)
        with self.assertRaises(Conflict):
            api.reserve(other_app, "1" * 32, "example.test")
        api.reserve(other_app, "2" * 32, "example.test")
        with self.assertRaises(Conflict):
            api.reserve(self.caller, "2" * 32, "example.test")

    def test_parallel_delete_and_prepare_cannot_restore_a_tombstone(self):
        self.seed()
        barrier = threading.Barrier(2)
        def prepare():
            barrier.wait(timeout=10)
            try:
                return self.api.prepare(self.caller, "1" * 32, CREDENTIAL, "example.test", "a" * 64)
            except Conflict:
                return None
        def delete():
            barrier.wait(timeout=10)
            return self.api.delete(self.caller, "2" * 32, CREDENTIAL)
        with concurrent.futures.ThreadPoolExecutor(2) as workers:
            preparation, deletion = workers.submit(prepare), workers.submit(delete)
            operation, tombstone = preparation.result(), deletion.result()
        credential = self.api.get_credential(self.caller, CREDENTIAL)
        self.assertEqual(credential["state"], "deleted")
        self.assertEqual(credential["counter"], 1 if operation else 0)
        if operation:
            self.assertEqual(self.store.read(self.caller.partition, f"operation-{operation['operation_id']}").value["state"], "cancelled")
        with self.assertRaises(Conflict):
            self.api.prepare(self.caller, "3" * 32, CREDENTIAL, "example.test", "b" * 64)
        self.assertEqual(self.api.delete(self.caller, "4" * 32, CREDENTIAL)["cleanup_id"], tombstone["cleanup_id"])

    def test_competing_deletions_allocate_one_cleanup_target(self):
        self.seed()
        with concurrent.futures.ThreadPoolExecutor(2) as workers:
            results = list(workers.map(lambda key: self.api.delete(self.caller, key * 32, CREDENTIAL), ["1", "2"]))
        self.assertEqual(results[0]["cleanup_id"], results[1]["cleanup_id"])

    def test_expired_worker_loses_claim_before_dispatch(self):
        self.seed()
        cleanup_id = self.api.delete(self.caller, "1" * 32, CREDENTIAL)["cleanup_id"]
        first = self.api.claim_cleanup(self.caller, "2" * 32, cleanup_id, "a" * 32)
        self.now = first["claim_until"]
        second = self.api.claim_cleanup(self.caller, "3" * 32, cleanup_id, "b" * 32)
        self.assertEqual(second["generation"], first["generation"] + 1)
        with self.assertRaises(Conflict):
            self.api.begin_cleanup(self.caller, "4" * 32, cleanup_id, "a" * 32, first["claim_token"])
        ticket = self.api.begin_cleanup(self.caller, "5" * 32, cleanup_id, "b" * 32, second["claim_token"])
        self.assertEqual(ticket["key_reference"], "private-key-generation-one")

    def test_dispatch_ticket_cannot_be_replayed_or_reclaimed(self):
        self.seed()
        cleanup_id = self.api.delete(self.caller, "1" * 32, CREDENTIAL)["cleanup_id"]
        claim = self.api.claim_cleanup(self.caller, "2" * 32, cleanup_id, "a" * 32)
        ticket = self.api.begin_cleanup(self.caller, "3" * 32, cleanup_id, "a" * 32, claim["claim_token"])
        for request in ["3", "4"]:
            with self.assertRaises(Conflict):
                self.api.begin_cleanup(self.caller, request * 32, cleanup_id, "a" * 32, claim["claim_token"])
        self.api.mark_cleanup_unknown(self.caller, "5" * 32, cleanup_id, ticket["dispatch_id"])
        self.now += 1000
        with self.assertRaises(Conflict):
            self.api.claim_cleanup(self.caller, "6" * 32, cleanup_id, "b" * 32)
        self.assertEqual(self.api.get_credential(self.caller, CREDENTIAL)["state"], "deleted")
        self.assertEqual(self.store.read(self.caller.partition, f"cleanup-{cleanup_id}").value["state"], "unknown")

    def test_wrong_cleanup_target_generation_cannot_dispatch(self):
        self.seed()
        cleanup_id = self.api.delete(self.caller, "1" * 32, CREDENTIAL)["cleanup_id"]
        claim = self.api.claim_cleanup(self.caller, "2" * 32, cleanup_id, "a" * 32)
        tx = Transaction(self.store, self.caller.partition)
        row = "credential-" + CREDENTIAL
        tx.put(row, {**tx.require(row, "credential"), "key_reference": "replacement-key-generation"})
        tx.commit()
        with self.assertRaises(Conflict):
            self.api.begin_cleanup(self.caller, "3" * 32, cleanup_id, "a" * 32, claim["claim_token"])
        self.assertEqual(self.store.read(self.caller.partition, f"cleanup-{cleanup_id}").value["state"], "claimed")

    def test_unknown_signing_blocks_cleanup_after_delete(self):
        self.seed()
        op = self.api.prepare(self.caller, "1" * 32, CREDENTIAL, "example.test", "a" * 64)
        tx = Transaction(self.store, self.caller.partition)
        row = f"operation-{op['operation_id']}"
        tx.put(row, {**tx.require(row, "operation"), "state": "unknown"})
        tx.commit()
        cleanup_id = self.api.delete(self.caller, "2" * 32, CREDENTIAL)["cleanup_id"]
        self.assertEqual(self.store.read(self.caller.partition, f"cleanup-{cleanup_id}").value["state"], "blocked")
        with self.assertRaises(Conflict):
            self.api.claim_cleanup(self.caller, "3" * 32, cleanup_id, "a" * 32)

    def test_another_owner_cannot_claim_cleanup(self):
        self.seed()
        cleanup_id = self.api.delete(self.caller, "1" * 32, CREDENTIAL)["cleanup_id"]
        with self.assertRaises(NotFound):
            self.api.claim_cleanup(caller(OTHER_OWNER), "2" * 32, cleanup_id, "a" * 32)
        public = self.api.get_credential(self.caller, CREDENTIAL)
        self.assertNotIn("key_reference", public)
        self.assertNotIn("claim_token", public)


class MemoryCoordinationTests(CoordinationCases, unittest.TestCase):
    pass


class UnknownCommitTests(unittest.TestCase):
    def test_mixed_revision_reads_are_not_false_corruption(self):
        class ConcurrentRevocation(MemoryStore):
            change = False
            def read(self, partition, row):
                if self.change and row == "credential-" + CREDENTIAL:
                    self.change = False
                    api = Coordinator(self, frozenset([APP]), lambda: 1000)
                    api.revoke(caller(), "a" * 32)
                    api.prepare(caller(), "b" * 32, CREDENTIAL, "example.test", "b" * 64)
                return super().read(partition, row)
        store = ConcurrentRevocation()
        seed_active(store, caller())
        store.change = True
        with self.assertRaises(Conflict):
            Coordinator(store, frozenset([APP]), lambda: 1000).prepare(caller(), "1" * 32, CREDENTIAL, "example.test", "a" * 64)
        self.assertEqual(store.read(caller().partition, "credential-" + CREDENTIAL).value["counter"], 1)

    def test_concurrent_owner_initialization_retries_the_entire_snapshot(self):
        class ConcurrentInitialization(MemoryStore):
            initialize = True
            def read(self, partition, row):
                if row == "request-" + "1" * 32 and self.initialize:
                    self.initialize = False
                    Coordinator(self, frozenset([APP]), lambda: 1000).reserve(caller(), "1" * 32, "example.test")
                return super().read(partition, row)
        store = ConcurrentInitialization()
        api = Coordinator(store, frozenset([APP]), lambda: 1000)
        result = api.reserve(caller(), "1" * 32, "example.test")
        self.assertEqual(api.get_credential(caller(), result["credential_id"])["state"], "reserved")
        self.assertEqual(store.read(caller().partition, "owner").value["revision"], 1)

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

    def test_lost_dispatch_acknowledgement_never_reissues_ticket(self):
        class LostAck(MemoryStore):
            fail = False
            def commit(self, *args):
                super().commit(*args)
                if self.fail:
                    self.fail = False
                    raise StorageUnavailable("lost acknowledgement")
        store = LostAck()
        api = Coordinator(store, frozenset([APP]), lambda: 1000)
        seed_active(store, caller())
        cleanup_id = api.delete(caller(), "1" * 32, CREDENTIAL)["cleanup_id"]
        claim = api.claim_cleanup(caller(), "2" * 32, cleanup_id, "a" * 32)
        store.fail = True
        with self.assertRaises(StorageUnavailable):
            api.begin_cleanup(caller(), "3" * 32, cleanup_id, "a" * 32, claim["claim_token"])
        with self.assertRaises(Conflict):
            api.begin_cleanup(caller(), "3" * 32, cleanup_id, "a" * 32, claim["claim_token"])
        self.assertEqual(store.read(caller().partition, f"cleanup-{cleanup_id}").value["state"], "dispatched")


if __name__ == "__main__":
    unittest.main()
