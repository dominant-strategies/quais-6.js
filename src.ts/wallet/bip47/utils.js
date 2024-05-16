import { bech32, bs58check, hash160 } from '@samouraiwallet/bip32/crypto';
export { hexToBytes, bytesToHex } from '@noble/hashes/utils';
export const networks = {
    bitcoin: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bech32: 'bc',
        bip32: {
            public: 0x0488b21e,
            private: 0x0488ade4,
        },
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
    },
    regtest: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bech32: 'bcrt',
        bip32: {
            public: 0x043587cf,
            private: 0x04358394,
        },
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
    },
    testnet: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bech32: 'tb',
        bip32: {
            public: 0x043587cf,
            private: 0x04358394,
        },
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
    }
};
export function xorUint8Arrays(a, b) {
    if (a.length !== b.length) {
        throw new Error('Uint8Arrays are not of the same length');
    }
    const result = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}
function toBase58Check(hash, version) {
    const payload = new Uint8Array(21);
    payload.set([version], 0);
    payload.set(hash, 1);
    return bs58check.encode(payload);
}
export function getP2pkhAddress(pubkey, network) {
    return toBase58Check(hash160(pubkey), network.pubKeyHash);
}
export function getP2shAddress(pubkey, network) {
    const push20 = new Uint8Array([0, 0x14]);
    const hash = hash160(pubkey);
    const scriptSig = new Uint8Array(push20.length + hash.length);
    scriptSig.set(push20);
    scriptSig.set(hash, push20.length);
    return toBase58Check(hash160(scriptSig), network.scriptHash);
}
export function getP2wpkhAddress(pubkey, network) {
    const hash = hash160(pubkey);
    const words = bech32.toWords(hash);
    words.unshift(0x00);
    return bech32.encode(network.bech32, words);
}