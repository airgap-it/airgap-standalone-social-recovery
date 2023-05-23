import * as bip39 from "bip39";
import { sha3_256 } from "js-sha3";
import secretJS from "secrets.js-grempe";

// Code taken from https://github.com/airgap-it/airgap-vault/blob/master/src/app/models/BIP39Signer.ts

export class BIPSigner {
  public readonly checkSumLength: number = 10;

  private getOffsetMapping(share: string): {
    offset: number;
    seedOffset: number;
  } {
    const shareWordCount: number = share.split(" ").length;

    switch (shareWordCount) {
      case 48:
        return { offset: 99, seedOffset: 64 };
      case 36:
        return { offset: 67, seedOffset: 42 };
      case 24:
        return { offset: 67, seedOffset: 32 };
      default:
        throw new Error(
          "Currently only recovery of secrets with 48, 36 or 24 words are supported"
        );
    }
  }

  public recoverKey(shares: any): string {
    const offset = this.getOffsetMapping(shares[0]);
    const translatedShares: string[] = [];
    for (let i = 0; i < shares.length; i++) {
      const words = shares[i].split(" ");
      const firstHalf = words.slice(0, 24);
      const secondHalf = words.slice(24, words.length);
      translatedShares[i] = `${bip39.mnemonicToEntropy(
        firstHalf.join(" ")
      )}${bip39.mnemonicToEntropy(secondHalf.join(" "))}`.substr(
        0,
        offset.offset
      );
    }
    const secretDigester = sha3_256.create();
    const combine = secretJS.combine(translatedShares);
    const seed = combine.slice(0, -this.checkSumLength);

    secretDigester.update(seed);

    const checksum = secretDigester.hex().slice(0, this.checkSumLength);
    const checksum2 = combine.substr(-this.checkSumLength);
    if (checksum !== checksum2) {
      throw new Error(
        "Checksum error, either the passed shares were generated for different secrets or the amount of shares is below the threshold"
      );
    }

    return bip39.entropyToMnemonic(seed);
  }
}
