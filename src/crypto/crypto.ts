import { createHash, createHmac, randomBytes } from "crypto";
import base58 from "bs58";
import {bech32, bech32m} from "bech32";

// hash functions
export function createEntropy(size: number): Buffer {
  return randomBytes(size);
}

export function hmacSeed(seed: Buffer): Buffer {
  return createHmac("sha512", Buffer.from("Bitcoin seed", "utf-8")).update(seed).digest();
}

export function sha256(key: Buffer): Buffer {
  return createHash("sha256").update(key).digest();
}

export function hash256(buffer: Buffer): Buffer {
  return sha256(sha256(buffer));
}

export function hash160(buffer: Buffer): Buffer {
  return createHash("ripemd160").update(sha256(buffer)).digest();
}

export function createChecksum(key: Buffer): Buffer {
  const firstSha = sha256(key);
  const secondSha = sha256(firstSha);
  return secondSha.subarray(0, 4);
}

// old base58 encoding
export function toBase58(buffer: Buffer): string {
  return base58.encode(buffer);
}

// old base58 decoding
export function fromBase58(base58String: string): Buffer {
  return Buffer.from(base58.decode(base58String))
}

// Função para codificar em Bech32 ou Bech32m
export function encode(data: Buffer, prefix: string, version: number): string {
  const dataArray = bech32.toWords(data);
  
  // Escolhe o método de codificação com base na versão
  if (version === 0) {
    return bech32.encode(prefix, dataArray);
  } else {
    return bech32m.encode(prefix, dataArray);
  }
}

// Função para decodificar de Bech32 ou Bech32m
export function decode(bech32String: string): { prefix: string; data: Buffer; version: number } {
  try {
    const { prefix, words } = bech32.decode(bech32String);
    // Se o checksum for válido para Bech32
    return { prefix, data: Buffer.from(bech32.fromWords(words)), version: 0 };
  } catch (bech32Error) {
    try {
      // Tenta Bech32m se Bech32 falhar
      const { prefix, words } = bech32m.decode(bech32String);
      return { prefix, data: Buffer.from(bech32.fromWords(words)), version: 1 };
    } catch (bech32mError) {
      throw new Error("Não é um endereço Bech32 ou Bech32m válido");
    }
  }
}

export const op = {
  OP_0: Buffer.from([0x00]),
  OP_DUP: Buffer.from([0x76]),
  OP_HASH160: Buffer.from([0xa9]),
  OP_EQUALVERIFY: Buffer.from([0x88]),
  OP_CHECKSIG: Buffer.from([0xac]),
  OP_EQUAL: Buffer.from([0x87]),
}