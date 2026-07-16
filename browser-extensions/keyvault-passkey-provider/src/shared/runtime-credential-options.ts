import { fromBase64Url, toBase64Url } from "./base64url";
import type {
  SerializedCredentialCreationOptions,
  SerializedCredentialOptions,
  SerializedPublicKeyCredentialDescriptor
} from "./protocol";

export function serializeRuntimeCredentialOptions(
  options: CredentialCreationOptions | CredentialRequestOptions
): SerializedCredentialOptions {
  if (isCreationOptions(options)) {
    return {
      ...options,
      publicKey: {
        ...options.publicKey,
        challenge: toBase64Url(toUint8Array(options.publicKey.challenge)),
        user: {
          ...options.publicKey.user,
          id: toBase64Url(toUint8Array(options.publicKey.user.id))
        },
        excludeCredentials: options.publicKey.excludeCredentials?.map(serializeDescriptor)
      }
    };
  }

  if (!isRequestOptions(options)) {
    throw new TypeError("Expected publicKey request options.");
  }

  return {
    ...options,
    publicKey: {
      ...options.publicKey,
      challenge: toBase64Url(toUint8Array(options.publicKey.challenge)),
      allowCredentials: options.publicKey.allowCredentials?.map(serializeDescriptor)
    }
  };
}

export function deserializeRuntimeCredentialOptions(
  options: SerializedCredentialOptions
): CredentialCreationOptions | CredentialRequestOptions {
  if (isSerializedCreationOptions(options)) {
    return {
      ...options,
      publicKey: {
        ...options.publicKey,
        challenge: toArrayBuffer(fromBase64Url(options.publicKey.challenge)),
        user: {
          ...options.publicKey.user,
          id: toArrayBuffer(fromBase64Url(options.publicKey.user.id))
        },
        excludeCredentials: options.publicKey.excludeCredentials?.map(deserializeDescriptor)
      }
    };
  }

  return {
    ...options,
    publicKey: {
      ...options.publicKey,
      challenge: toArrayBuffer(fromBase64Url(options.publicKey.challenge)),
      allowCredentials: options.publicKey.allowCredentials?.map(deserializeDescriptor)
    }
  };
}

function serializeDescriptor(descriptor: PublicKeyCredentialDescriptor): SerializedPublicKeyCredentialDescriptor {
  return {
    ...descriptor,
    id: toBase64Url(toUint8Array(descriptor.id))
  };
}

function deserializeDescriptor(descriptor: SerializedPublicKeyCredentialDescriptor): PublicKeyCredentialDescriptor {
  return {
    ...descriptor,
    id: toArrayBuffer(fromBase64Url(descriptor.id))
  };
}

function isCreationOptions(
  options: CredentialCreationOptions | CredentialRequestOptions
): options is CredentialCreationOptions & { publicKey: PublicKeyCredentialCreationOptions } {
  return Boolean(options.publicKey && "user" in options.publicKey && "rp" in options.publicKey && "pubKeyCredParams" in options.publicKey);
}

function isRequestOptions(
  options: CredentialCreationOptions | CredentialRequestOptions
): options is CredentialRequestOptions & { publicKey: PublicKeyCredentialRequestOptions } {
  return Boolean(options.publicKey && !("user" in options.publicKey) && !("rp" in options.publicKey) && !("pubKeyCredParams" in options.publicKey));
}

function isSerializedCreationOptions(
  options: SerializedCredentialOptions
): options is SerializedCredentialCreationOptions {
  return Boolean(options.publicKey && "user" in options.publicKey && "rp" in options.publicKey && "pubKeyCredParams" in options.publicKey);
}

function toUint8Array(value: BufferSource): Uint8Array {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return new Uint8Array(value).buffer;
}