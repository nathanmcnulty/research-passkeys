import { encodeArray, encodeBoolean, encodeByteString, encodeInteger, encodeMap, encodeTextString } from "./cbor";

const defaultAaguidHex = "33867143325B48D0ADFCE7AE975FE068";

export async function buildMakeCredentialAuthenticatorData(
  rpId: string,
  credentialId: Uint8Array,
  x: Uint8Array,
  y: Uint8Array,
  signCount = 0,
  userVerified = false,
  backupEligible = false,
  backupState = false,
  extensions: Array<[string, Uint8Array]> = [],
  aaguidHex = defaultAaguidHex
): Promise<Uint8Array> {
  const rpIdHash = await sha256(new TextEncoder().encode(rpId));
  const publicKey = buildCosePublicKey(x, y);
  const extensionsData = buildAuthenticatorExtensionsData(extensions);
  const result = new Uint8Array(32 + 1 + 4 + 16 + 2 + credentialId.length + publicKey.length + extensionsData.length);
  let offset = 0;

  result.set(rpIdHash, offset);
  offset += rpIdHash.length;
  result[offset] = buildFlags({
    userPresent: true,
    userVerified,
    attestedCredentialData: true,
    backupEligible,
    backupState,
    extensionDataIncluded: extensionsData.length > 0
  });
  offset += 1;
  writeUint32BigEndian(result, offset, signCount);
  offset += 4;
  result.set(hexToBytes(aaguidHex), offset);
  offset += 16;
  writeUint16BigEndian(result, offset, credentialId.length);
  offset += 2;
  result.set(credentialId, offset);
  offset += credentialId.length;
  result.set(publicKey, offset);
  offset += publicKey.length;

  if (extensionsData.length > 0) {
    result.set(extensionsData, offset);
  }

  return result;
}

export async function buildAssertionAuthenticatorData(rpId: string, signCount: number): Promise<Uint8Array> {
  return buildAssertionAuthenticatorDataWithFlags(rpId, signCount, false);
}

export async function buildAssertionAuthenticatorDataWithFlags(
  rpId: string,
  signCount: number,
  userVerified: boolean,
  backupEligible = false,
  backupState = false,
  extensions: Array<[string, Uint8Array]> = []
): Promise<Uint8Array> {
  const rpIdHash = await sha256(new TextEncoder().encode(rpId));
  const extensionsData = buildAuthenticatorExtensionsData(extensions);
  const result = new Uint8Array(32 + 1 + 4 + extensionsData.length);
  result.set(rpIdHash, 0);
  result[32] = buildFlags({
    userPresent: true,
    userVerified,
    attestedCredentialData: false,
    backupEligible,
    backupState,
    extensionDataIncluded: extensionsData.length > 0
  });
  writeUint32BigEndian(result, 33, signCount);

  if (extensionsData.length > 0) {
    result.set(extensionsData, 37);
  }

  return result;
}

export function buildCosePublicKey(x: Uint8Array, y: Uint8Array): Uint8Array {
  return encodeMap([
    [encodeInteger(1), encodeInteger(2)],
    [encodeInteger(3), encodeInteger(-7)],
    [encodeInteger(-1), encodeInteger(1)],
    [encodeInteger(-2), encodeByteString(x)],
    [encodeInteger(-3), encodeByteString(y)]
  ]);
}

export function buildEcP256SubjectPublicKeyInfo(x: Uint8Array, y: Uint8Array): Uint8Array {
  const uncompressedPoint = new Uint8Array(1 + x.length + y.length);
  uncompressedPoint[0] = 0x04;
  uncompressedPoint.set(x, 1);
  uncompressedPoint.set(y, 1 + x.length);

  const prefix = new Uint8Array([
    0x30, 0x59,
    0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00
  ]);

  const result = new Uint8Array(prefix.length + uncompressedPoint.length);
  result.set(prefix, 0);
  result.set(uncompressedPoint, prefix.length);
  return result;
}

export function buildNoneAttestationObject(authenticatorData: Uint8Array): Uint8Array {
  return encodeMap([
    [encodeTextString("fmt"), encodeTextString("none")],
    [encodeTextString("attStmt"), encodeMap([])],
    [encodeTextString("authData"), encodeByteString(authenticatorData)]
  ]);
}

export function buildPackedAttestationObject(
  authenticatorData: Uint8Array,
  signature: Uint8Array,
  certificates: Uint8Array[] = []
): Uint8Array {
  const attestationStatementEntries: Array<[Uint8Array, Uint8Array]> = [
    [encodeTextString("alg"), encodeInteger(-7)],
    [encodeTextString("sig"), encodeByteString(signature)]
  ];

  if (certificates.length > 0) {
    attestationStatementEntries.push([
      encodeTextString("x5c"),
      encodeArray(certificates.map((certificate) => encodeByteString(certificate)))
    ]);
  }

  return encodeMap([
    [encodeTextString("fmt"), encodeTextString("packed")],
    [encodeTextString("attStmt"), encodeMap(attestationStatementEntries)],
    [encodeTextString("authData"), encodeByteString(authenticatorData)]
  ]);
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", toPlainArrayBuffer(value));
  return new Uint8Array(digest);
}

function writeUint16BigEndian(target: Uint8Array, offset: number, value: number) {
  target[offset] = (value >> 8) & 0xff;
  target[offset + 1] = value & 0xff;
}

function writeUint32BigEndian(target: Uint8Array, offset: number, value: number) {
  target[offset] = (value >> 24) & 0xff;
  target[offset + 1] = (value >> 16) & 0xff;
  target[offset + 2] = (value >> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

function hexToBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    bytes[index / 2] = Number.parseInt(value.slice(index, index + 2), 16);
  }

  return bytes;
}

function buildFlags(flags: {
  userPresent: boolean;
  userVerified: boolean;
  attestedCredentialData: boolean;
  backupEligible: boolean;
  backupState: boolean;
  extensionDataIncluded: boolean;
}): number {
  let value = 0;
  if (flags.userPresent) {
    value |= 0x01;
  }

  if (flags.userVerified) {
    value |= 0x04;
  }

  if (flags.backupEligible) {
    value |= 0x08;
  }

  if (flags.backupState) {
    value |= 0x10;
  }

  if (flags.attestedCredentialData) {
    value |= 0x40;
  }

  if (flags.extensionDataIncluded) {
    value |= 0x80;
  }

  return value;
}

function buildAuthenticatorExtensionsData(extensions: Array<[string, Uint8Array]>): Uint8Array {
  if (extensions.length === 0) {
    return new Uint8Array();
  }

  const encodedEntries = extensions
    .map(([key, value]) => [encodeTextString(key), value] as const)
    .sort(([leftKey], [rightKey]) => compareLexicographically(leftKey, rightKey));

  return encodeMap(encodedEntries.map(([key, value]) => [key, value]));
}

function compareLexicographically(left: Uint8Array, right: Uint8Array): number {
  const sharedLength = Math.min(left.length, right.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = left[index] - right[index];
    if (difference !== 0) {
      return difference;
    }
  }

  return left.length - right.length;
}

export function buildBooleanAuthenticatorExtensionOutput(value: boolean): Uint8Array {
  return encodeBoolean(value);
}

function toPlainArrayBuffer(value: Uint8Array): ArrayBuffer {
  return new Uint8Array(value).buffer;
}
