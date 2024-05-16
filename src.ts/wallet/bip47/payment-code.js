import { BIP32Factory } from '@samouraiwallet/bip32';
import { bs58check, hmacSHA512 } from '@samouraiwallet/bip32/crypto';
import { sha256 } from '@noble/hashes/sha256';
import * as utils from './utils.js';
const PC_VERSION = 0x47;
const SAMOURAI_FEATURE_BYTE = 79;
export class PaymentCodePublic {
    constructor(ecc, bip32, buf, network = utils.networks.bitcoin) {
        this.ecc = ecc;
        this.bip32 = bip32;
        this.hasPrivKeys = false;
        if (buf.length !== 80)
            throw new Error('Invalid buffer length');
        if (buf[0] !== 1)
            throw new Error('Only payment codes version 1 are supported');
        this.buf = buf;
        this.network = network;
        this.segwit = this.buf[SAMOURAI_FEATURE_BYTE] === 1;
        this.root = bip32.fromPublicKey(this.pubKey, this.chainCode, this.network);
    }
    get features() {
        return this.buf.subarray(1, 2);
    }
    get pubKey() {
        return this.buf.subarray(2, 2 + 33);
    }
    get chainCode() {
        return this.buf.subarray(35, 35 + 32);
    }
    get paymentCode() {
        return this.buf;
    }
    clone() {
        return new PaymentCodePublic(this.ecc, this.bip32, this.buf.slice(0), this.network);
    }
    toBase58() {
        const version = new Uint8Array([PC_VERSION]);
        const buf = new Uint8Array(version.length + this.buf.length);
        buf.set(version);
        buf.set(this.buf, version.length);
        return bs58check.encode(buf);
    }
    derive(index) {
        return this.root.derive(index);
    }
    getNotificationPublicKey() {
        return this.derive(0).publicKey;
    }
    getNotificationAddress() {
        return utils.getP2pkhAddress(this.getNotificationPublicKey(), this.network);
    }
    derivePublicKeyFromSharedSecret(B, S) {
        if (!this.ecc.isPoint(B))
            throw new Error('Invalid derived public key');
        if (!S)
            throw new Error('Unable to compute secret point');
        const Sx = S.subarray(1, 33);
        const s = sha256(Sx);
        if (!this.ecc.isPrivate(s))
            throw new Error('Invalid shared secret');
        const EccPoint = this.ecc.pointFromScalar(s);
        if (!EccPoint)
            throw new Error('Unable to compute point');
        const paymentPublicKey = this.ecc.pointAdd(B, EccPoint);
        if (!paymentPublicKey)
            throw new Error('Unable to compute payment public key');
        return paymentPublicKey;
    }
    derivePaymentPublicKey(paymentCode, idx) {
        const a = paymentCode.getNotificationPrivateKey();
        if (!this.ecc.isPrivate(a))
            throw new Error('Received invalid private key');
        const B = this.derive(idx).publicKey;
        const S = this.ecc.pointMultiply(B, a);
        return this.derivePublicKeyFromSharedSecret(B, S);
    }
    getAddressFromPubkey(pubKey, type) {
        switch (type) {
            case 'p2pkh': {
                return utils.getP2pkhAddress(pubKey, this.network);
            }
            case 'p2sh': {
                return utils.getP2shAddress(pubKey, this.network);
            }
            case 'p2wpkh': {
                return utils.getP2wpkhAddress(pubKey, this.network);
            }
            default: {
                throw new Error(`Unknown address type. Expected: p2pkh | p2sh | p2wpkh, got ${type}`);
            }
        }
    }
    getPaymentAddress(paymentCode, idx, type = 'p2pkh') {
        const pubKey = this.derivePaymentPublicKey(paymentCode, idx);
        return this.getAddressFromPubkey(pubKey, type);
    }
    getBlindedPaymentCode(destinationPaymentCode, outpoint, privateKey) {
        const a = privateKey;
        const B = destinationPaymentCode.getNotificationPublicKey();
        const S = this.ecc.pointMultiply(B, a);
        if (!S)
            throw new Error('Unable to compute secret point');
        const x = S.subarray(1, 33);
        const o = outpoint;
        const s = hmacSHA512(o, x);
        const paymentCodeBuffer = this.paymentCode;
        const blindedPaymentCode = paymentCodeBuffer.slice(0);
        blindedPaymentCode.set(utils.xorUint8Arrays(s.subarray(0, 32), paymentCodeBuffer.subarray(3, 35)), 3);
        blindedPaymentCode.set(utils.xorUint8Arrays(s.subarray(32, 64), paymentCodeBuffer.subarray(35, 67)), 35);
        return utils.bytesToHex(blindedPaymentCode);
    }
}
export class PaymentCodePrivate extends PaymentCodePublic {
    constructor(root, ecc, bip32, buf, network = utils.networks.bitcoin) {
        super(ecc, bip32, buf, network);
        this.root = root;
        this.hasPrivKeys = true;
    }
    toPaymentCodePublic() {
        return new PaymentCodePublic(this.ecc, this.bip32, this.buf.slice(0), this.network);
    }
    clone() {
        return new PaymentCodePrivate(this.root, this.ecc, this.bip32, this.buf.slice(0), this.network);
    }
    deriveHardened(index) {
        return this.root.deriveHardened(index);
    }
    derivePaymentPublicKey(paymentCode, idx) {
        const A = paymentCode.getNotificationPublicKey();
        if (!this.ecc.isPoint(A))
            throw new Error('Received invalid public key');
        const b_node = this.derive(idx);
        if (!b_node.privateKey)
            throw new Error('Unable to derive node with private key');
        const b = b_node.privateKey;
        const B = b_node.publicKey;
        const S = this.ecc.pointMultiply(A, b);
        return this.derivePublicKeyFromSharedSecret(B, S);
    }
    getPaymentAddress(paymentCode, idx, type = 'p2pkh') {
        const pubKey = this.derivePaymentPublicKey(paymentCode, idx);
        return this.getAddressFromPubkey(pubKey, type);
    }
    derivePaymentPrivateKey(paymentCodePublic, idx) {
        const A = paymentCodePublic.getNotificationPublicKey();
        if (!this.ecc.isPoint(A))
            throw new Error('Argument is not a valid public key');
        const b_node = this.derive(idx);
        if (!b_node.privateKey)
            throw new Error('Unable to derive node without private key');
        const b = b_node.privateKey;
        const S = this.ecc.pointMultiply(A, b);
        if (!S)
            throw new Error('Unable to compute resulting point');
        const Sx = S.subarray(1, 33);
        const s = sha256(Sx);
        if (!this.ecc.isPrivate(s))
            throw new Error('Invalid shared secret');
        const paymentPrivateKey = this.ecc.privateAdd(b, s);
        if (!paymentPrivateKey)
            throw new Error('Unable to compute payment private key');
        return paymentPrivateKey;
    }
    getNotificationPrivateKey() {
        const child = this.derive(0);
        return child.privateKey;
    }
    getPaymentCodeFromNotificationTransactionData(scriptPubKey, outpoint, pubKey) {
        if (!(scriptPubKey.length === 83 && scriptPubKey[0] === 0x6a && scriptPubKey[1] === 0x4c && scriptPubKey[2] === 0x50))
            throw new Error('Invalid OP_RETURN payload');
        const A = pubKey;
        const b = this.getNotificationPrivateKey();
        const S = this.ecc.pointMultiply(A, b);
        if (!S)
            throw new Error('Unable to compute secret point');
        const x = S.subarray(1, 33);
        const s = hmacSHA512(outpoint, x);
        const blindedPaymentCode = scriptPubKey.subarray(3);
        const paymentCodeBuffer = blindedPaymentCode.slice(0);
        paymentCodeBuffer.set(utils.xorUint8Arrays(s.subarray(0, 32), blindedPaymentCode.subarray(3, 35)), 3);
        paymentCodeBuffer.set(utils.xorUint8Arrays(s.subarray(32, 64), blindedPaymentCode.subarray(35, 67)), 35);
        return new PaymentCodePublic(this.ecc, this.bip32, paymentCodeBuffer, this.network);
    }
}
export const BIP47Factory = (ecc) => {
    const bip32 = BIP32Factory(ecc);
    const fromSeed = (bSeed, segwit = false, network = utils.networks.bitcoin) => {
        const root = bip32.fromSeed(bSeed);
        const coinType = (network.pubKeyHash === utils.networks.bitcoin.pubKeyHash) ? '0' : '1';
        const root_bip47 = root.derivePath(`m/47'/${coinType}'/0'`);
        const pc = new Uint8Array(80);
        pc.set([1, 0]);
        if (root_bip47.publicKey.length !== 33)
            throw new Error('Missing or wrong publicKey');
        pc.set(root_bip47.publicKey, 2);
        if (root_bip47.chainCode.length !== 32)
            throw new Error('Missing or wrong chainCode');
        pc.set(root_bip47.chainCode, 35);
        if (segwit) {
            pc[SAMOURAI_FEATURE_BYTE] = 1;
        }
        return new PaymentCodePrivate(root_bip47, ecc, bip32, pc, network);
    };
    const fromBase58 = (inString, network) => {
        const buf = bs58check.decode(inString);
        const version = buf[0];
        if (version !== PC_VERSION)
            throw new Error('Invalid version');
        return new PaymentCodePublic(ecc, bip32, buf.slice(1), network);
    };
    const fromBuffer = (buf, network) => {
        return new PaymentCodePublic(ecc, bip32, buf, network);
    };
    return {
        fromSeed,
        fromBase58,
        fromBuffer
    };
};