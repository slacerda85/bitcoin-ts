import { createChecksum, hash160, hmacSeed } from "@/crypto";
import { bech32 } from "bech32";
import { entropyToMnemonic, mnemonicToSeedSync } from "bip39";
import wordList from "bip39/src/wordlists/english.json";
import { createHmac } from "crypto";
import secp256k1 from "secp256k1";

export function toMnemonic(entropy: Buffer): string {
  // check if nBytes is a valid length of 128, 160, 192, 224, or 256 bits
  if (entropy.length % 4 !== 0 || entropy.length < 16 || entropy.length > 32) {
    throw new Error("Invalid mnemonic length");
  }
  return entropyToMnemonic(entropy, wordList);
}

export function fromMnemonic(mnemonic: string): Buffer {
  const seed  = mnemonicToSeedSync(mnemonic);
  return seed;
}

// bip32 master key creation
export function createMasterKey(entropy: Buffer): {
  masterKey: Buffer;
  chainCode: Buffer;
} {
  const extendedSeed = hmacSeed(entropy);
  const masterKey = extendedSeed.subarray(0, 32);

  if (!secp256k1.privateKeyVerify(masterKey)) {
    throw new Error("This entropy cannot generate a valid ECDSA private key");
  }

  const chainCode = extendedSeed.subarray(32);

  return {
    masterKey,
    chainCode,
  };
}

export function createPublicKey(privateKey: Buffer): Buffer {
  // check if the private key is valid
  if (!secp256k1.privateKeyVerify(privateKey)) {
    throw new Error("Invalid private key");
  }

  let publicKey: Buffer;

    do {
      publicKey = Buffer.from(secp256k1.publicKeyCreate(privateKey));
    } while (!secp256k1.publicKeyVerify(publicKey));

    return publicKey;
}

function deriveChildPrivateKey(privateKey: Buffer, chainCode: Buffer, index: number) {
  const isHardened = index >= 0x80000000;
  const n = BigInt(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  );

  // mount the data to be hashed
  const privateKeyPadding = Buffer.allocUnsafe(1);
  privateKeyPadding.writeUInt8(0, 0);

  const indexBuffer = Buffer.allocUnsafe(4);
  indexBuffer.writeUInt32BE(index, 0);

  const key = isHardened
    ? Buffer.concat([privateKeyPadding, privateKey])
    : createPublicKey(privateKey);

  const data = Buffer.concat([key, indexBuffer]);
  const hmac = createHmac("sha512", chainCode).update(data).digest();
  const derivedKey = hmac.subarray(0, 32);
  const childChainCode = hmac.subarray(32);
  const parse256IL = BigInt(`0x${derivedKey.toString("hex")}`);
  if (parse256IL >= n) {
    throw new Error(
      "Derived key is invalid (greater or equal to curve order)."
    );
  }

  const kpar = BigInt(`0x${privateKey.toString("hex")}`);
  const ki = (parse256IL + kpar) % n;

  if (ki === BigInt(0)) {
    throw new Error("Derived key is invalid (zero value).");
  }

  const childKey = Buffer.from(ki.toString(16).padStart(64, "0"), "hex");

  return { childKey, childChainCode };
}

function createHardenedIndex(index: number): number {
  const HARDENED_OFFSET = 0x80000000; // This is 2^31 in hexadecimal
  return index + HARDENED_OFFSET;
}

function getParentFingerprint(publicKey: Buffer): number {
  const hash = hash160(publicKey);
  const parentFingerprint = hash.subarray(0, 4).readUInt32BE(0);
  return parentFingerprint;
}

function convertPathToArray(path: string) {
  const pathArray: number[] = [];
  const segments = path.split("/").slice(1); // remove the first element (m)
  segments.forEach((segment) => {
    if (segment.endsWith("'")) {
      pathArray.push(
        createHardenedIndex(parseInt(segment.slice(0, -1), 10))
      );
    } else {
      pathArray.push(parseInt(segment, 10));
    }
  });

  return pathArray;
}

export function deriveFromPath(
  privateKey: Buffer,
  chainCode: Buffer,
  path: string
): {
  derivedKey: Buffer;
  derivedChainCode: Buffer;
  childIndex: number;
  parentFingerprint: number;
  depth: number;
} {
  if (privateKey.length !== 32) {
    throw new Error("Invalid master key");
  }
  const pathArray = path.split("/");
  if (pathArray[0] !== "m") {
    throw new Error("Invalid path");
  }
  if (path === "m") {
    return {
      derivedKey: privateKey,
      derivedChainCode: chainCode,
      childIndex: 0,
      parentFingerprint: 0,
      depth: 0,
    };   
    
  }
  // split the path into segments
  const segments = convertPathToArray(path);
  let privKey = privateKey;
  let chain = chainCode;
  let parentFingerprint = 0;
  let childNumber = 0;
  let depth = 0;

  // iterate over the path segments of bip32
  for (let i = 0; i < segments.length; i++) {
    const index = segments[i];
    const { childKey, childChainCode } = deriveChildPrivateKey(
      privKey,
      chain,
      index
    );
    const parentPublicKey = createPublicKey(privKey);
    parentFingerprint = getParentFingerprint(parentPublicKey);
    privKey = childKey;
    chain = childChainCode;
    childNumber = index;
    depth++;
  }

  return {
    derivedKey: privKey,
    derivedChainCode: chain,
    childIndex: childNumber,
    parentFingerprint,
    depth,
  };
}

export function serializePrivateKey(
  privateKey: Buffer,
  chainCode: Buffer,
  depth: number = 0,
  parentFingerprint: number = 0,
  childIndex: number = 0,
  version: Buffer
): Buffer {
  // check valid private key
  if (!secp256k1.privateKeyVerify(privateKey)) {
    throw new Error("Invalid private key");
  }
  // check valid chain code
  if (chainCode.length !== 32) {
    throw new Error("Invalid chain code");
  }
  // check valid depth
  if (depth > 255) {
    throw new Error("Invalid depth");
  }
  // check valid parent fingerprint
  if (parentFingerprint > 0xffffffff) {
    throw new Error("Invalid parent fingerprint");
  }
  // check valid child index
  if (childIndex > 0xffffffff) {
    throw new Error("Invalid child index");
  }

  // serialize private key
  // mount private key buffer
  const privateKeyBuffer = Buffer.allocUnsafe(78);
  // version number
  const versionNumber = parseInt(version.toString("hex"), 16);
  privateKeyBuffer.writeUint32BE(versionNumber, 0);
  privateKeyBuffer.writeUInt8(depth, 4);
  privateKeyBuffer.writeUInt32BE(parentFingerprint, 5);
  privateKeyBuffer.writeUInt32BE(childIndex, 9);
  chainCode.copy(privateKeyBuffer, 13);
  privateKeyBuffer.writeUInt8(0, 45); // 0 for private key
  privateKey.copy(privateKeyBuffer, 46);
  // create checksum
  const checksum = createChecksum(privateKeyBuffer);
  const finalKey = Buffer.concat([privateKeyBuffer, checksum]);

  return finalKey;
}

export function serializePublicKey(
  publicKey: Buffer,
  chainCode: Buffer,
  depth: number = 0,
  parentFingerprint: number = 0,
  childIndex: number = 0,
  version: Buffer
): Buffer {
  // check valid public key
  if (!secp256k1.publicKeyVerify(publicKey)) {
    throw new Error("Invalid public key");
  }
  // check valid depth
  if (depth > 255) {
    throw new Error("Invalid depth");
  }
  // check valid parent fingerprint
  if (parentFingerprint > 0xffffffff) {
    throw new Error("Invalid parent fingerprint");
  }
  // check valid child index
  if (childIndex > 0xffffffff) {
    throw new Error("Invalid child index");
  }
  // serialize public key
  // mount public key buffer
  const publicKeyBuffer = Buffer.allocUnsafe(78);
  // version number
  const versionNumber = parseInt(version?.toString("hex"), 16);
  publicKeyBuffer.writeUint32BE(versionNumber, 0);
  publicKeyBuffer.writeUInt8(depth, 4);
  publicKeyBuffer.writeUInt32BE(parentFingerprint, 5);
  publicKeyBuffer.writeUInt32BE(childIndex, 9);
  chainCode.copy(publicKeyBuffer, 13);
  publicKey.copy(publicKeyBuffer, 45);
  // create checksum
  const checksum = createChecksum(publicKeyBuffer);
  const finalKey = Buffer.concat([publicKeyBuffer, checksum]);

  return finalKey;
}

export function serializePublicKeyForSegWit(
  publicKey: Buffer,
  version: number = 0
): string {
  // Check if the public key is valid
  if (!secp256k1.publicKeyVerify(publicKey)) {
    throw new Error("Invalid public key");
  }

  // Hash the public key using SHA256 and then RIPEMD160
  const hash = hash160(publicKey);

  // Convert the hash to words (5-bit groups)
  const programWords = bech32.toWords(hash);

  // Prepend the version byte to the words array
  const words = [version, ...programWords];

  // Encode using Bech32
  const segWitAddress = bech32.encode('bc', words);

  return segWitAddress;
}