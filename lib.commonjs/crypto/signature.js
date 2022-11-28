"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Signature = void 0;
const index_js_1 = require("../constants/index.js");
const index_js_2 = require("../utils/index.js");
// Constants
const BN_0 = BigInt(0);
const BN_1 = BigInt(1);
const BN_2 = BigInt(2);
const BN_27 = BigInt(27);
const BN_28 = BigInt(28);
const BN_35 = BigInt(35);
const _guard = {};
class Signature {
    #props;
    get r() { return (0, index_js_2.getStore)(this.#props, "r"); }
    set r(value) {
        (0, index_js_2.assertArgument)((0, index_js_2.dataLength)(value) === 32, "invalid r", "value", value);
        (0, index_js_2.setStore)(this.#props, "r", (0, index_js_2.hexlify)(value));
    }
    get s() { return (0, index_js_2.getStore)(this.#props, "s"); }
    set s(value) {
        (0, index_js_2.assertArgument)((0, index_js_2.dataLength)(value) === 32, "invalid r", "value", value);
        (0, index_js_2.assertArgument)(((0, index_js_2.getBytes)(value)[0] & 0x80) === 0, "non-canonical s", "value", value);
        (0, index_js_2.setStore)(this.#props, "s", (0, index_js_2.hexlify)(value));
    }
    get v() { return (0, index_js_2.getStore)(this.#props, "v"); }
    set v(value) {
        const v = (0, index_js_2.getNumber)(value, "value");
        (0, index_js_2.assertArgument)(v === 27 || v === 28, "invalid v", "v", value);
        (0, index_js_2.setStore)(this.#props, "v", v);
    }
    get networkV() { return (0, index_js_2.getStore)(this.#props, "networkV"); }
    get legacyChainId() {
        const v = this.networkV;
        if (v == null) {
            return null;
        }
        return Signature.getChainId(v);
    }
    get yParity() {
        return (this.v === 27) ? 0 : 1;
    }
    get yParityAndS() {
        // The EIP-2098 compact representation
        const yParityAndS = (0, index_js_2.getBytes)(this.s);
        if (this.yParity) {
            yParityAndS[0] |= 0x80;
        }
        return (0, index_js_2.hexlify)(yParityAndS);
    }
    get compactSerialized() {
        return (0, index_js_2.concat)([this.r, this.yParityAndS]);
    }
    get serialized() {
        return (0, index_js_2.concat)([this.r, this.s, (this.yParity ? "0x1c" : "0x1b")]);
    }
    constructor(guard, r, s, v) {
        (0, index_js_2.assertPrivate)(guard, _guard, "Signature");
        this.#props = { r, s, v, networkV: null };
    }
    [Symbol.for('nodejs.util.inspect.custom')]() {
        return `Signature { r: "${this.r}", s: "${this.s}", yParity: ${this.yParity}, networkV: ${this.networkV} }`;
    }
    clone() {
        const clone = new Signature(_guard, this.r, this.s, this.v);
        if (this.networkV) {
            (0, index_js_2.setStore)(clone.#props, "networkV", this.networkV);
        }
        return clone;
    }
    freeze() {
        Object.freeze(this.#props);
        return this;
    }
    isFrozen() {
        return Object.isFrozen(this.#props);
    }
    toJSON() {
        const networkV = this.networkV;
        return {
            _type: "signature",
            networkV: ((networkV != null) ? networkV.toString() : null),
            r: this.r, s: this.s, v: this.v,
        };
    }
    // Get the chain ID from an EIP-155 v
    static getChainId(v) {
        const bv = (0, index_js_2.getBigInt)(v, "v");
        // The v is not an EIP-155 v, so it is the unspecified chain ID
        if ((bv == BN_27) || (bv == BN_28)) {
            return BN_0;
        }
        // Bad value for an EIP-155 v
        (0, index_js_2.assertArgument)(bv >= BN_35, "invalid EIP-155 v", "v", v);
        return (bv - BN_35) / BN_2;
    }
    // Get the EIP-155 v transformed for a given chainId
    static getChainIdV(chainId, v) {
        return ((0, index_js_2.getBigInt)(chainId) * BN_2) + BigInt(35 + v - 27);
    }
    // Convert an EIP-155 v into a normalized v
    static getNormalizedV(v) {
        const bv = (0, index_js_2.getBigInt)(v);
        if (bv == BN_0) {
            return 27;
        }
        if (bv == BN_1) {
            return 28;
        }
        // Otherwise, EIP-155 v means odd is 27 and even is 28
        return (bv & BN_1) ? 27 : 28;
    }
    static from(sig) {
        function assertError(check, message) {
            (0, index_js_2.assertArgument)(check, message, "signature", sig);
        }
        ;
        if (sig == null) {
            return new Signature(_guard, index_js_1.ZeroHash, index_js_1.ZeroHash, 27);
        }
        if (typeof (sig) === "string") {
            const bytes = (0, index_js_2.getBytes)(sig, "signature");
            if (bytes.length === 64) {
                const r = (0, index_js_2.hexlify)(bytes.slice(0, 32));
                const s = bytes.slice(32, 64);
                const v = (s[0] & 0x80) ? 28 : 27;
                s[0] &= 0x7f;
                return new Signature(_guard, r, (0, index_js_2.hexlify)(s), v);
            }
            if (bytes.length === 65) {
                const r = (0, index_js_2.hexlify)(bytes.slice(0, 32));
                const s = bytes.slice(32, 64);
                assertError((s[0] & 0x80) === 0, "non-canonical s");
                const v = Signature.getNormalizedV(bytes[64]);
                return new Signature(_guard, r, (0, index_js_2.hexlify)(s), v);
            }
            assertError(false, "invlaid raw signature length");
        }
        if (sig instanceof Signature) {
            return sig.clone();
        }
        // Get r
        const r = sig.r;
        assertError(r != null, "missing r");
        assertError((0, index_js_2.isHexString)(r, 32), "invalid r");
        // Get s; by any means necessary (we check consistency below)
        const s = (function (s, yParityAndS) {
            if (s != null) {
                assertError((0, index_js_2.isHexString)(s, 32), "invalid s");
                return s;
            }
            if (yParityAndS != null) {
                assertError((0, index_js_2.isHexString)(yParityAndS, 32), "invalid yParityAndS");
                const bytes = (0, index_js_2.getBytes)(yParityAndS);
                bytes[0] &= 0x7f;
                return (0, index_js_2.hexlify)(bytes);
            }
            assertError(false, "missing s");
        })(sig.s, sig.yParityAndS);
        assertError(((0, index_js_2.getBytes)(s)[0] & 0x80) == 0, "non-canonical s");
        // Get v; by any means necessary (we check consistency below)
        const { networkV, v } = (function (_v, yParityAndS, yParity) {
            if (_v != null) {
                const v = (0, index_js_2.getBigInt)(_v);
                return {
                    networkV: ((v >= BN_35) ? v : undefined),
                    v: Signature.getNormalizedV(v)
                };
            }
            if (yParityAndS != null) {
                assertError((0, index_js_2.isHexString)(yParityAndS, 32), "invalid yParityAndS");
                return { v: (((0, index_js_2.getBytes)(yParityAndS)[0] & 0x80) ? 28 : 27) };
            }
            if (yParity != null) {
                switch (yParity) {
                    case 0: return { v: 27 };
                    case 1: return { v: 28 };
                }
                assertError(false, "invalid yParity");
            }
            assertError(false, "missing v");
        })(sig.v, sig.yParityAndS, sig.yParity);
        const result = new Signature(_guard, r, s, v);
        if (networkV) {
            (0, index_js_2.setStore)(result.#props, "networkV", networkV);
        }
        // If multiple of v, yParity, yParityAndS we given, check they match
        assertError(!("yParity" in sig && sig.yParity !== result.yParity), "yParity mismatch");
        assertError(!("yParityAndS" in sig && sig.yParityAndS !== result.yParityAndS), "yParityAndS mismatch");
        return result;
    }
}
exports.Signature = Signature;
//# sourceMappingURL=signature.js.map