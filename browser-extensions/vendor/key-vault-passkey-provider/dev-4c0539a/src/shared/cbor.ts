function encodeLength(majorType: number, length: number): number[] {
  if (length < 24) {
    return [(majorType << 5) | length];
  }

  if (length < 0x100) {
    return [(majorType << 5) | 24, length];
  }

  if (length < 0x10000) {
    return [(majorType << 5) | 25, (length >> 8) & 0xff, length & 0xff];
  }

  throw new Error("CBOR length is too large for this encoder.");
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const buffer = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    buffer.set(part, offset);
    offset += part.length;
  }

  return buffer;
}

export function encodeByteString(value: Uint8Array): Uint8Array {
  return concat([new Uint8Array(encodeLength(2, value.length)), value]);
}

export function encodeTextString(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  return concat([new Uint8Array(encodeLength(3, bytes.length)), bytes]);
}

export function encodeInteger(value: number): Uint8Array {
  if (Number.isInteger(value) === false) {
    throw new Error("Only integer values are supported.");
  }

  if (value >= 0) {
    return new Uint8Array(encodeLength(0, value));
  }

  return new Uint8Array(encodeLength(1, (-1 * value) - 1));
}

export function encodeBoolean(value: boolean): Uint8Array {
  return new Uint8Array([value ? 0xf5 : 0xf4]);
}

export function encodeMap(entries: Array<[Uint8Array, Uint8Array]>): Uint8Array {
  const body = entries.flatMap(([key, value]) => [key, value]);
  return concat([new Uint8Array(encodeLength(5, entries.length)), ...body]);
}

export function encodeArray(values: Uint8Array[]): Uint8Array {
  return concat([new Uint8Array(encodeLength(4, values.length)), ...values]);
}
