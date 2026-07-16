export type BrowserStoredCredentialRecord = {
  recordId: string;
  credentialId: string;
  rpId: string;
  userHandle: string;
  userName: string;
  userDisplayName: string;
  signingKeyId: string;
  backendKind: string;
  createdAt: string;
  updatedAt: string;
  signCount: number;
};

export type BrowserCredentialEnvelope = {
  version: string;
  recordId: string;
  contentKeyProtection: string;
  updatedAt: string;
  ciphertext: string;
  protectedContentKey: string;
  metadataKeyId: string | null;
  nonce: string;
  tag: string;
  tenantId?: string | null;
  userObjectId?: string | null;
  credentialId?: string | null;
  rpId?: string | null;
  userHandle?: string | null;
  signingKeyId?: string | null;
  backendKind?: string | null;
};

export type MetadataSummary = {
  storedCredentialCount: number;
  relyingPartyCount: number;
  lastUpdatedAt: string | null;
};
