import bip32vectors from "./test-vectors/bip32-vectors"
import bip49Vectors from "./test-vectors/bip49-vectors"
import Wallet from "./wallet";
import {createPublicKey, deriveFromPath, serializePrivateKey, serializePublicKey} from '@/key'
import {toBase58, fromBase58, encode, decode} from '@/crypto'
import bip84Vectors from "./test-vectors/bip84-vectors";

describe("Wallet", () => {
  test("Create wallet", () => {
    const wallet = new Wallet();
    expect(wallet).toBeDefined();
  });

  // BIP32 HD wallet
  describe("BIP32 HD wallet", () => {
    bip32vectors.forEach((vector, index) => {
      const wallet = new Wallet(
        Buffer.from(vector?.seed as string, "hex"),
        vector?.mnemonic
      );
  
      describe(`Test vector ${index + 1}`, () => {
        Object.keys(vector?.chains)?.forEach((path) => {
          test (`path ${path}`, () => {
            const derivedKey = deriveFromPath(
              wallet.privateKey,
              wallet.chainCode,
              path
            );
            
            const serializedPrivateKey = serializePrivateKey(
              derivedKey.derivedKey,
              derivedKey.derivedChainCode,
              derivedKey.depth,
              derivedKey.parentFingerprint,
              derivedKey.childIndex,
              Buffer.from([0x04, 0x88, 0xad, 0xe4]), // xprv
            );

            const publicKey = createPublicKey(derivedKey.derivedKey);

            const serializedPublicKey = serializePublicKey(
              publicKey,
              derivedKey.derivedChainCode,
              derivedKey.depth,
              derivedKey.parentFingerprint,
              derivedKey.childIndex,
              Buffer.from([0x04, 0x88, 0xb2, 0x1e]), // xpub
            )
    
            const privKeyHash = toBase58(serializedPrivateKey);
            const pubKeyHash = toBase58(serializedPublicKey);
    
            expect(privKeyHash).toBe(vector.chains[path].privKey);
            expect(pubKeyHash).toBe(vector.chains[path].pubKey);
          })
        });
      });
    });
  })

  // BIP49 HD wallet
  describe("BIP49 HD wallet", () => {
    bip49Vectors.forEach((vector, index) => {
      const wallet = new Wallet(
        undefined,
        vector?.mnemonic
      );
  
      describe(`Test vector ${index + 1}`, () => {
        Object.keys(vector?.chains)?.forEach((path) => {
          test (`path ${path}`, () => {
            const derivedKey = deriveFromPath(
              wallet.privateKey,
              wallet.chainCode,
              path
            );

            const serializedPrivateKey = serializePrivateKey(
              derivedKey.derivedKey,
              derivedKey.derivedChainCode,
              derivedKey.depth,
              derivedKey.parentFingerprint,
              derivedKey.childIndex,
              Buffer.from([0x04, 0x4a, 0x4e, 0x28]), // uprv
            );

            const publicKey = createPublicKey(derivedKey.derivedKey);

            const serializedPublicKey = serializePublicKey(
              publicKey,
              derivedKey.derivedChainCode,
              derivedKey.depth,
              derivedKey.parentFingerprint,
              derivedKey.childIndex,
              Buffer.from([0x04, 0x4a, 0x52, 0x62]), // upub
            )

            const privKeyHash = toBase58(serializedPrivateKey);
            const pubKeyHash = toBase58(serializedPublicKey);
    
            expect(privKeyHash).toBe(vector.chains[path].privKey);
            expect(pubKeyHash).toBe(vector.chains[path].pubKey);
          })
        });
      });
    });
  })

  // BIP84 HD wallet
  describe("BIP84 HD wallet", () => {
    bip84Vectors.forEach((vector, index) => {
      const wallet = new Wallet(
        undefined,
        vector?.mnemonic
      );
  
      describe(`Test vector ${index + 1}`, () => {
        Object.keys(vector?.chains)?.forEach((path) => {
          describe(`path ${path}`, () => {
            const derivedKey = deriveFromPath(
              wallet.privateKey,
              wallet.chainCode,
              path
            );

            const serializedPrivateKey = serializePrivateKey(
              derivedKey.derivedKey,
              derivedKey.derivedChainCode,
              derivedKey.depth,
              derivedKey.parentFingerprint,
              derivedKey.childIndex,
              Buffer.from([0x04, 0xb2, 0x43, 0x0c]), // zprv
            );

            const publicKey = createPublicKey(derivedKey.derivedKey);

            const serializedPublicKey = serializePublicKey(
              publicKey,
              derivedKey.derivedChainCode,
              derivedKey.depth,
              derivedKey.parentFingerprint,
              derivedKey.childIndex,
              Buffer.from([0x04, 0xb2, 0x47, 0x46]), // zpub
            )

            const privKeyHash = toBase58(serializedPrivateKey);
            const pubKeyHash = toBase58(serializedPublicKey);

            const address = encode(publicKey, 'bc', 0);
    
            test('zprv/zpub', () => {
              if (vector.chains[path].privKey.startsWith('zprv') && vector.chains[path].pubKey.startsWith('zpub')) {
                expect(privKeyHash).toBe(vector.chains[path].privKey);
                expect(pubKeyHash).toBe(vector.chains[path].pubKey);
              }
            })
            test('address', () => {
              if (vector.chains[path].address) {
                expect(address).toBe(vector.chains[path].address);
              }
            })
          })
        });
      });
    });
  })
});
