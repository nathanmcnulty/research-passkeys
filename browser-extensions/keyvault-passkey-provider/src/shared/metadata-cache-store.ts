import type { BrowserCredentialEnvelope, MetadataSummary } from "./models";

const databaseName = "kvpp-browser-extension";
const databaseVersion = 1;
const credentialsStoreName = "credential-envelopes";

type EnvelopeRecord = {
  recordId: string;
  envelope: BrowserCredentialEnvelope;
};

export async function saveEnvelopeToCache(recordId: string, envelope: BrowserCredentialEnvelope): Promise<void> {
  const database = await openDatabase();
  await runTransaction(database, "readwrite", (store) => {
    store.put({ recordId, envelope } satisfies EnvelopeRecord);
  });
}

export async function loadEnvelopesFromCache(): Promise<BrowserCredentialEnvelope[]> {
  const database = await openDatabase();
  const envelopeRecords = await runTransaction<EnvelopeRecord[]>(database, "readonly", (store, resolve, reject) => {
    const request = store.getAll();
    request.onsuccess = () => resolve((request.result as EnvelopeRecord[]) ?? []);
    request.onerror = () => reject(request.error ?? new Error("Failed to load stored credential envelopes."));
  });

  return envelopeRecords.map((record) => record.envelope);
}

export async function deleteEnvelopeFromCache(recordId: string): Promise<void> {
  const database = await openDatabase();
  await runTransaction(database, "readwrite", (store) => {
    store.delete(recordId);
  });
}

export async function getCachedMetadataSummary(): Promise<MetadataSummary> {
  const envelopes = await loadEnvelopesFromCache();
  const relyingPartySet = new Set<string>();
  let lastUpdatedAt: string | null = null;

  for (const envelope of envelopes) {
    if (envelope.rpId) {
      relyingPartySet.add(envelope.rpId);
    }

    if (!lastUpdatedAt || envelope.updatedAt > lastUpdatedAt) {
      lastUpdatedAt = envelope.updatedAt;
    }
  }

  return {
    storedCredentialCount: envelopes.length,
    relyingPartyCount: relyingPartySet.size,
    lastUpdatedAt
  };
}

async function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, databaseVersion);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(credentialsStoreName)) {
        database.createObjectStore(credentialsStoreName, { keyPath: "recordId" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Failed to open metadata database."));
  });
}

async function runTransaction<TResult = void>(
  database: IDBDatabase,
  mode: IDBTransactionMode,
  callback: (store: IDBObjectStore, resolve: (value: TResult) => void, reject: (error: unknown) => void) => void
): Promise<TResult> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(credentialsStoreName, mode);
    const store = transaction.objectStore(credentialsStoreName);
    let settled = false;

    transaction.onabort = () => {
      if (!settled) {
        settled = true;
        reject(transaction.error ?? new Error("IndexedDB transaction was aborted."));
      }
    };

    transaction.onerror = () => {
      if (!settled) {
        settled = true;
        reject(transaction.error ?? new Error("IndexedDB transaction failed."));
      }
    };

    transaction.oncomplete = () => {
      if (!settled) {
        settled = true;
        resolve(undefined as TResult);
      }
    };

    callback(
      store,
      (value) => {
        if (!settled) {
          settled = true;
          resolve(value);
        }
      },
      (error) => {
        if (!settled) {
          settled = true;
          reject(error);
        }
      }
    );
  });
}
