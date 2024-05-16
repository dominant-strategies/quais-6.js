# @samouraiwallet/bip47

A set of utilities for working with BIP47 and bitcoinjs-lib.

This library uses ES Modules. Node.js v16 or later is required.
This library does not use any Node.js built-ins and thus is browser compatible.

Source code was written in Typescript. Type definitions are included in the published bundle.

## Contents

- [Installation](#installation)
- [API documentation](#api-documentation)
- Usage
  - [ECC library](#ecc-library)
  - [Examples](#examples)
  - [Interfaces](#interfaces)

## Installation

```bash
npm install @samouraiwallet/bip47
```

or

```bash
pnpm add @samouraiwallet/bip47
```

or

```bash
yarn add @samouraiwallet/bip47
```

## API documentation

Generated API documentation is available in the git repository. To view latest API docs locally, you can run these commands.

```bash
# create a temp folder
mkdir bip47-docs
cd bip47-docs

# download and extract docs directory
curl -fsSL https://code.samourai.io/dojo/bip47-js/-/archive/master/bip47-js-master.tar.gz\?path\=docs | tar -xzv --strip-components=2

# run simple HTTP file server
npx serve .
```

## Usage

### ECC library

You need to provide an implementation of `secp256k1` elliptic curve.

Supported libraries:

- [tiny-secp256k1](https://github.com/bitcoinjs/tiny-secp256k1) - Rust implementation compiled to Webassembly, work in Node.js and browsers but might require reconfiguring your bundler
- [@bitcoinerlab/secp256k1](https://github.com/bitcoinerlab/secp256k1) - Javascript implementation which works everywhere but has a lower performance

### Examples

- [Create an instance of bip47](#create-an-instance-of-bip47)
- [Create a PaymetCodePrivate instance from wallet master seed](#create-a-paymetcodeprivate-instance-from-wallet-master-seed)
- [Create a PaymetCodePublic instance from payment code string](#create-a-paymetcodepublic-instance-from-payment-code-string)
- [Generate a base58 encoded payment code](#generate-a-base58-encoded-payment-code)
- [Get notification address](#get-notification-address)
- [Get notification address public key](#get-notification-address-public-key)
- [Get notification address private key](#get-notification-address-private-key)
- [Derive addresses from Alice to Bob](#derive-addresses-from-alice-to-bob)
- [Derive payment keys from Alice to Bob](#derive-payment-keys-from-alice-to-bob)
- [Extract payment code from notification transaction](#extract-payment-code-from-notification-transaction)
- [Get blinded payment code for notification transaction](#get-blinded-payment-code-for-notification-transaction)

#### Create an instance of bip47

```ts
import BIP47Factory from "@samouraiwallet/bip47";
import * as ecc from "tiny-secp256k1";

const bip47 = BIP47Factory(ecc);
```

#### Create a PaymetCodePrivate instance from wallet master seed

**on mainnet**

```ts
import type { PaymentCodePrivate } from "@samouraiwallet/bip47";

let walletSeed: Uint8Array;

const alice: PaymentCodePrivate = bip47.fromSeed(walletSeed);

// with segwit support
const alice2: PaymentCodePrivate = bip47.fromSeed(walletSeed, true);
```

**on testnet**

```ts
import type { PaymentCodePrivate } from "@samouraiwallet/bip47";
import { networks } from "@samouraiwallet/bip47/utils";

let walletSeed: Uint8Array;

// pass in a desired network object (bitcoin | testnet | regtest) from utils or directly from bitcoinjs-lib
const alice: PaymentCodePrivate = bip47.fromSeed(
  walletSeed,
  false,
  networks["testnet"]
);
// with segwit support
const alice2: PaymentCodePrivate = bip47.fromSeed(
  walletSeed,
  true,
  networks["testnet"]
);
```

#### Create a PaymetCodePublic instance from payment code string

**on mainnet**

```ts
import type { PaymentCodePublic } from "@samouraiwallet/bip47";

const pcode =
  "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";

const bob: PaymentCodePublic = bip47.fromBase58(pcode);
```

**on testnet**

```ts
import type { PaymentCodePublic } from "@samouraiwallet/bip47";
import { networks } from "@samouraiwallet/bip47/utils";

const pcode =
  "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";

// pass in a desired network object (bitcoin | testnet | regtest) from utils or directly from bitcoinjs-lib
const bob: PaymentCodePublic = bip47.fromBase58(pcode, networks["testnet"]);
```

#### Generate a base58 encoded payment code

```ts
const alicePcode: string = alice.toBase58(); // PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA
```

#### Get notification address

```ts
const aliceNotificationAddress: string = alice.getNotificationAddress(); // 1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW
```

#### Get notification address public key

```ts
const aliceNotifPubKey: Uint8Array = alice.getNotificationPublicKey(); // 0353883a146a23f988e0f381a9507cbdb3e3130cd81b3ce26daf2af088724ce683
```

#### Get notification address private key

```ts
const aliceNotifPrivKey: Uint8Array = alice.getNotificationPrivateKey(); // 8d6a8ecd8ee5e0042ad0cb56e3a971c760b5145c3917a8e7beaf0ed92d7a520c
```

#### Derive addresses from Alice to Bob

**Alice's side**

```ts
// Bob's P2PKH address at index 0
const bobAddress: string = bob.getPaymentAddress(alice, 0, "p2pkh"); // 141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK

// check if Bob's payment code supports receiving to segwit addresses
if (bob.segwit) {
  // Bob's P2WPKH address at index 1
  const bobSegwitAddress = bob.getPaymentAddress(alice, 1, "p2wpkh"); // bc1qzn8a8drxv6ln7rztjsw660gzf3hnrfwupzmsfh
}
```

**Bob's side**

```ts
import type {
  PaymentCodePrivate,
  PaymentCodePublic,
} from "@samouraiwallet/bip47";

let bobSeed: Uint8Array;
let alicePcode: string; // base58 encoded payment code

const bob: PaymentCodePrivate = bip47.fromSeed(bobSeed);
const alice: PaymentCodePublic = bip47.fromBase58(alicePcode);

const bobAddress: string = bob.getPaymentAddress(alice, 0, "p2pkh"); // 141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK
```

#### Derive payment keys from Alice to Bob

**Alice's side**

```ts
// Bob's payment pubkey at index 0
const bobPubKey: Uint8Array = bob.derivePaymentPublicKey(alice, 0); // 0344b4795e48df097bd87e6cf87a70e4f0c30b2d847b6e34cddde64af10296952d
```

**Bob's side**

```ts
import type {
  PaymentCodePrivate,
  PaymentCodePublic,
} from "@samouraiwallet/bip47";

let bobSeed: Uint8Array;
let alicePcode: string; // base58 encoded payment code

const bob: PaymentCodePrivate = bip47.fromSeed(bobSeed);
const alice: PaymentCodePublic = bip47.fromBase58(alicePcode);

// Bob's payment keys at index 0
const bobPubKey: Uint8Array = bob.derivePaymentPublicKey(alice, 0);
const bobPrivKey: Uint8Array = bob.derivePaymentPrivateKey(alice, 0);
```

#### Extract payment code from notification transaction

```ts
import type {
  PaymentCodePrivate,
  PaymentCodePublic,
} from "@samouraiwallet/bip47";

let bobSeed: Uint8Array;
const bob: PaymentCodePrivate = bip47.fromSeed(bob.seed);

let scriptPubKey: Uint8Array; // scriptPubKey of notification transaction OP_RETURN output
let outpoint: Uint8Array; // outpoint of first input of notification transaction
let pubKey: Uint8Array; // public key of first input of notification transaction

const alice: PaymentCodePublic =
  bob.getPaymentCodeFromNotificationTransactionData(
    scriptPubKey,
    outpoint,
    pubKey
  );
const alicePcode: string = alice.toBase58(); // PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA
```

In order to extract payment code from a notification transaction, the scriptPubKey, outpoint and pubKey must be provided.
You can use `bitcoinjs-lib` to extract these values from a transaction.

```ts
import * as bitcoin from "bitcoinjs-lib";

let notificationTxHex: string;

const tx: bitcoin.Transaction = bitcoin.Transaction.fromHex(notificationTxHex);

const opReturnOutput = tx.outs.find(
  (o) => o.script[0] === 0x6a && o.script[1] === 0x4c && o.script[2] === 0x50
);

if (!opReturnOutput)
  throw new error("Transaction doesn't contain OP_RETURN output");

const scriptPubKey: Uint8Array = opReturnOutput.script;

const input = tx.ins[0];
const outpoint: Uint8Array = new Uint8Array(input.hash.length + 4);
outpoint.set(input.hash);
outpoint.set(new Uint32Array([input.index]), input.hash.length);

let pubKey: Uint8Array;

if (input.witness.length) {
  pubKey = input.witness[1];
} else if (bitcoin.script.toASM(input.script).split(" ").length === 2) {
  pubKey = Buffer.from(bitcoin.script.toASM(input.script).split(" ")[1], "hex");
} else throw new Error("Unknown Transaction type");
```

#### Get blinded payment code for notification transaction

```ts
let outpoint: Uint8Array; // outpoint of the first input of the notification transaction
let privKey: Uint8Array; // private key of a first input of the notification transaction

const blindedAlicePcode: string = alicePcode.getBlindedPaymentCode(
  bob,
  outpoint,
  privKey
);
```

### Interfaces

```ts
export declare const BIP47Factory: (ecc: TinySecp256k1Interface) => {
  fromSeed: (
    bSeed: Uint8Array,
    segwit?: boolean,
    network?: Network
  ) => PaymentCodePrivate;
  fromBase58: (inString: string, network?: Network) => PaymentCodePublic;
  fromBuffer: (buf: Uint8Array, network?: Network) => PaymentCodePublic;
};

export declare class PaymentCodePublic {
  protected readonly ecc: TinySecp256k1Interface;
  protected readonly bip32: BIP32API;
  protected readonly buf: Uint8Array;
  protected readonly network: Network;
  root: BIP32Interface;
  hasPrivKeys: boolean;
  segwit: boolean;

  constructor(
    ecc: TinySecp256k1Interface,
    bip32: BIP32API,
    buf: Uint8Array,
    network?: Network
  );

  get features(): Uint8Array;

  get pubKey(): Uint8Array;

  get chainCode(): Uint8Array;

  get paymentCode(): Uint8Array;

  clone(): PaymentCodePublic;

  toBase58(): string;

  derive(index: number): BIP32Interface;

  getNotificationPublicKey(): Uint8Array;

  getNotificationAddress(): string;

  protected derivePublicKeyFromSharedSecret(
    B: Uint8Array,
    S: Uint8Array | null
  ): Uint8Array;

  derivePaymentPublicKey(
    paymentCode: PaymentCodePrivate,
    idx: number
  ): Uint8Array;

  protected getAddressFromPubkey(pubKey: Uint8Array, type: AddressType): string;

  getPaymentAddress(
    paymentCode: PaymentCodePrivate,
    idx: number,
    type?: AddressType
  ): string;

  getBlindedPaymentCode(
    destinationPaymentCode: PaymentCodePublic,
    outpoint: Uint8Array,
    privateKey: Uint8Array
  ): string;
}

export declare class PaymentCodePrivate extends PaymentCodePublic {
  constructor(
    root: BIP32Interface,
    ecc: TinySecp256k1Interface,
    bip32: BIP32API,
    buf: Uint8Array,
    network?: Network
  );

  toPaymentCodePublic(): PaymentCodePublic;

  clone(): PaymentCodePrivate;

  deriveHardened(index: number): BIP32Interface;

  derivePaymentPublicKey(
    paymentCode: PaymentCodePublic,
    idx: number
  ): Uint8Array;

  getPaymentAddress(
    paymentCode: PaymentCodePublic,
    idx: number,
    type?: AddressType
  ): string;

  derivePaymentPrivateKey(
    paymentCodePublic: PaymentCodePublic,
    idx: number
  ): Uint8Array;

  getNotificationPrivateKey(): Uint8Array;

  getPaymentCodeFromNotificationTransactionData(
    scriptPubKey: Uint8Array,
    outpoint: Uint8Array,
    pubKey: Uint8Array
  ): PaymentCodePublic;
}
```
