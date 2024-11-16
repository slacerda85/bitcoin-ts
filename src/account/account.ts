import { createPublicKey, deriveFromPath, serializePrivateKey, serializePublicKey } from "@/key/key";

function discover(
    privateKey: Buffer,
    chainCode: Buffer,
    purpose = 44,
    coinType = 0,
    gapLimit: number = 20
  ) {
    const accounts = [];
    let accountIndex = 0;

    while (true) {
      // derive first account node      
      const accountNode = deriveFromPath(
        privateKey,
        chainCode,
        `m/${purpose}'/${coinType}'/${accountIndex}'/0`
      );
      // derive external chain node
      const externalChainNode = deriveFromPath(
        accountNode.derivedKey,
        accountNode.derivedChainCode,
        `0`
      ); // this turns previous "m/44'/0'/0'/0" into "m/44'/0'/0'/0/0"

      // scan addresses of the external chain
      let usedAddresses = 0;
      for (let i = 0; i < gapLimit; i++) {
        const {
            derivedKey,
            derivedChainCode,
            childIndex,
            depth,
            parentFingerprint,
        }
        = deriveFromPath(
          externalChainNode.derivedKey,
          externalChainNode.derivedChainCode,
          `${i}`
        )

        const publicKey = createPublicKey(derivedKey);
        const address = serializePublicKey(
        publicKey,
        derivedChainCode,
        depth,
        parentFingerprint,
        childIndex,
        Buffer.from([0x04, 0x88, 0xad, 0xe4]), // xprv
        );

        // Simulate checking for transactions (replace with actual transaction check)
        const hasTransactions = checkForTransactions(address);

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

  function checkForTransactions(address: Buffer) {
    // Simulate checking for transactions (replace with actual transaction check)
    console.log(
      `Checking for transactions for address: ${address.toString("hex")}`
    );
    return Math.random() < 0.5;
  }