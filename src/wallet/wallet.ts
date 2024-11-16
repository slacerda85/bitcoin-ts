// import { createHmac, randomBytes } from "crypto";
// import secp256k1 from "secp256k1";
// import bs58 from "bs58";
// import wordList from "bip39/src/wordlists/english.json";
// import { entropyToMnemonic, mnemonicToSeedSync } from "bip39";
// import { hash160, createChecksum } from "../crypto";

import { createEntropy, hmacSeed } from "@/crypto";
import { createMasterKey, createPublicKey, fromMnemonic, serializePrivateKey, serializePublicKey, toMnemonic } from "@/key";

const VERSION = {
  mainnet: {
    prv: Buffer.from([0x04, 0x88, 0xad, 0xe4]), // xprv
    pub: Buffer.from([0x04, 0x88, 0xb2, 0x1e]), // xpub
  },
  testnet: {
    prv: Buffer.from([0x04, 0x35, 0x83, 0x94]), // tprv
    pub: Buffer.from([0x04, 0x35, 0x87, 0xcf]), // tpub
  },
};

export default class Wallet {
  #mnemonic: string;
  #privateKey: Buffer;
  #chainCode: Buffer;
  #publicKey: Buffer;

  constructor(
    bytes?: Buffer,
    mnemonic?: string,
    privateKey?: Buffer | string,
  ) {
    if (bytes) {
      const { masterKey, chainCode } = createMasterKey(bytes);
      this.#privateKey = masterKey;
      this.#mnemonic = toMnemonic(this.#privateKey);
      this.#chainCode = chainCode;
    } else if (privateKey) {
      // TODO: validate private key
      this.#privateKey =
        typeof privateKey === "string"
          ? this.#toBuffer(privateKey)
          : privateKey;
      this.#mnemonic = toMnemonic(this.#privateKey);      
      this.#chainCode = hmacSeed(this.#privateKey).subarray(32);
    } else if (mnemonic) {
      this.#mnemonic = mnemonic;
      const seed = fromMnemonic(mnemonic);      
      const { masterKey, chainCode } = createMasterKey(seed);
      this.#privateKey = masterKey;
      this.#chainCode = chainCode;
    } else {
      const { masterKey, chainCode } = createMasterKey(
        createEntropy(32)
      );
      this.#privateKey = masterKey;
      this.#mnemonic = toMnemonic(this.#privateKey);
      this.#chainCode = chainCode
    }
    this.#publicKey = createPublicKey(this.#privateKey);    
    
  }

  get privateKey() {
    return this.#privateKey;
  }

  get chainCode() {
    return this.#chainCode;
  }

  get mnemonic() {
    return this.#mnemonic;
  }

  get publicKey() {
    return this.#publicKey.toString("hex");
  }

  #toBuffer(string: string): Buffer {
    return Buffer.from(string, "hex");
  }
/* 
  #toBuffer(string: string): Buffer {
    return Buffer.from(string, "hex");
  }

  #createMnemonic(numberOfWords: 12 | 24): {
    privateKey: Buffer;
    mnemonic: string;
  } {
    const bytes = numberOfWords === 12 ? 16 : 32;
    const privateKey = this.#createPrivateKey(bytes);
    this.#privateKey = privateKey;
    return {
      mnemonic: entropyToMnemonic(privateKey),
      privateKey,
    };
  }

  #createPrivateKey(nBytes: number): Buffer {
    let privateKey: Uint8Array;

    do {
      const entropy = randomBytes(nBytes);
      privateKey = this.#extendPrivateKey(entropy).privateKey;
    } while (!secp256k1.privateKeyVerify(privateKey));

    return Buffer.from(privateKey);
  }

  #getPublicKey(privateKey: Buffer): Buffer {
    if (!secp256k1.privateKeyVerify(privateKey)) {
      throw new Error("Invalid private key");
    }

    let publicKey: Buffer;

    do {
      publicKey = Buffer.from(secp256k1.publicKeyCreate(privateKey));
    } while (!secp256k1.publicKeyVerify(publicKey));

    return publicKey;
  }

  #extendPrivateKey(privateKey: Buffer): {
    privateKey: Buffer;
    chainCode: Buffer;
  } {
    let extendedSeed: Buffer;
    let key: Buffer;

    do {
      extendedSeed = createHmac("sha512", Buffer.from("Bitcoin seed", "utf-8"))
        .update(privateKey)
        .digest();
      key = extendedSeed.subarray(0, 32);
    } while (!secp256k1.privateKeyVerify(key));

    const chainCode = extendedSeed.subarray(32);

    return {
      privateKey: key,
      chainCode,
    };
  }

  #serializePrivateKey(
    privateKey: Buffer,
    chainCode: Buffer,
    depth: number = 0,
    parentFingerprint: number = 0,
    childIndex: number = 0
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
    const versionNumber = parseInt(VERSION.mainnet.prv.toString("hex"), 16);
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

  #serializePublicKey(
    publicKey: Buffer,
    chainCode: Buffer,
    depth: number = 0,
    parentFingerprint: number = 0,
    childIndex: number = 0
  ): Buffer {
    // check valid public key
    if (!secp256k1.publicKeyVerify(this.#publicKey)) {
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
    const versionNumber = parseInt(VERSION.mainnet.pub.toString("hex"), 16);
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

  encodeBase58(buffer: Buffer): string {
    return bs58.encode(buffer);
  }

  decodeBase58(string: string): Buffer {
    return Buffer.from(bs58.decode(string));
  }

  deriveChildPrivateKey(privateKey: Buffer, chainCode: Buffer, index: number) {
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
      : this.#getPublicKey(privateKey);

    const data = Buffer.concat([key, indexBuffer]);
    const hmac = createHmac("sha512", chainCode).update(data).digest();
    const derivedKey = hmac.subarray(0, 32);
    const derivedChainCode = hmac.subarray(32);
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

    return { childKey, derivedChainCode };
  }

  deriveKeyFromPath(
    privateKey: Buffer,
    chainCode: Buffer,
    path: string
  ): {
    privateKey: Buffer;
    chain: Buffer;
    serializedExtendedPrivateKey: Buffer;
    serializedExtendedPublicKey: Buffer;
  } {
    if (privateKey.length !== 32) {
      throw new Error("Invalid master key");
    }
    const pathArray = path.split("/");
    if (pathArray[0] !== "m") {
      throw new Error("Invalid path");
    }
    if (path === "m") {
      const publicKey = this.#getPublicKey(privateKey);

      const serializedExtendedPrivateKey = this.#serializePrivateKey(
        privateKey,
        chainCode
      );
      const serializedExtendedPublicKey = this.#serializePublicKey(
        publicKey,
        chainCode
      );
      return {
        privateKey,
        chain: chainCode,
        serializedExtendedPrivateKey,
        serializedExtendedPublicKey,
      };
    }
    // split the path into segments
    const segments = this.convertPathToArray(path);
    let privKey = privateKey;
    let chain = chainCode;
    let parentFingerprint = 0;
    let childNumber = 0;
    let depth = 0;

    // iterate over the path segments of bip32
    for (let i = 0; i < segments.length; i++) {
      const index = segments[i];
      const { childKey, derivedChainCode } = this.deriveChildPrivateKey(
        privKey,
        chain,
        index
      );
      const parentPublicKey = this.#getPublicKey(privKey);
      parentFingerprint = this.getParentFingerprint(parentPublicKey);
      privKey = childKey;
      chain = derivedChainCode;
      childNumber = index;
      depth++;
    }

    const publicKey = this.#getPublicKey(privKey);

    const serializedExtendedPrivateKey = this.#serializePrivateKey(
      privKey,
      chain,
      depth,
      parentFingerprint,
      childNumber
    );
    const serializedExtendedPublicKey = this.#serializePublicKey(
      publicKey,
      chain,
      depth,
      parentFingerprint,
      childNumber
    );
    return {
      privateKey: privKey,
      chain,
      serializedExtendedPrivateKey,
      serializedExtendedPublicKey,
    };
  }

  convertPathToArray(path: string) {
    const pathArray: number[] = [];
    const segments = path.split("/").slice(1); // remove the first element (m)
    segments.forEach((segment) => {
      if (segment.endsWith("'")) {
        pathArray.push(
          this.createHardenedIndex(parseInt(segment.slice(0, -1), 10))
        );
      } else {
        pathArray.push(parseInt(segment, 10));
      }
    });

    return pathArray;
  }

  createHardenedIndex(index: number): number {
    const HARDENED_OFFSET = 0x80000000; // This is 2^31 in hexadecimal
    return index + HARDENED_OFFSET;
  }

  getParentFingerprint(publicKey: Buffer): number {
    const hash = hash160(publicKey);
    const parentFingerprint = hash.subarray(0, 4).readUInt32BE(0);
    return parentFingerprint;
  }

  discoverAccounts(
    privateKey: Buffer,
    purpose = 44,
    coinType = 0,
    gapLimit: number = 20
  ) {
    const accounts = [];
    let accountIndex = 0;

    while (true) {
      // derive first account node
      const { chainCode } = this.#extendPrivateKey(privateKey);
      const accountNode = this.deriveKeyFromPath(
        privateKey,
        chainCode,
        `m/${purpose}'/${coinType}'/${accountIndex}'`
      );
      // derive external chain node
      const externalChainNode = this.deriveKeyFromPath(
        accountNode.privateKey,
        accountNode.chain,
        `0`
      ); // this turns previous "m/44'/0'/0'" into "m/44'/0'/0'/0"

      // scan addresses of the external chain
      let usedAddresses = 0;
      for (let i = 0; i < gapLimit; i++) {
        const address = this.deriveKeyFromPath(
          externalChainNode.privateKey,
          externalChainNode.chain,
          `${i}`
        ).serializedExtendedPublicKey;

        // Simulate checking for transactions (replace with actual transaction check)
        const hasTransactions = this.#checkForTransactions(address);

        if (hasTransactions) {
          usedAddresses++;
        } else {
          break;
        }
      }

      if (usedAddresses === 0) {
        break;
      }

      accounts.push({
        accountIndex,
        usedAddresses,
      });

      accountIndex++;
    }

    return accounts;
  }

  #checkForTransactions(address: Buffer) {
    return Math.random() < 0.5;
  } */
}
