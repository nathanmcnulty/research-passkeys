import os
import unittest
from uuid import uuid4

from kvpp_broker.storage import AzureTableStore
from test_coordination import CoordinationCases


def emulator_store(table):
    from azure.core.credentials import AzureNamedKeyCredential
    return AzureTableStore.from_endpoint(os.environ["KVPP_TABLE_EMULATOR_ENDPOINT"], table,
        AzureNamedKeyCredential("brokerlocal", "Yg=="), allow_local_emulator=True)


@unittest.skipUnless(os.environ.get("KVPP_TABLE_EMULATOR_ENDPOINT"), "Run the local Azurite harness for real ETag transactions.")
class AzureTableCoordinationTests(CoordinationCases, unittest.TestCase):
    def make_store(self):
        store = emulator_store("Broker" + uuid4().hex)
        store.client.create_table()
        self.addCleanup(store.client.close)
        self.addCleanup(store.client.delete_table)
        return store


if __name__ == "__main__":
    unittest.main()
