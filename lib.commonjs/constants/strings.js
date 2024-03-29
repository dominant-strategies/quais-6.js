"use strict";
// NFKC (composed)             // (decomposed)
Object.defineProperty(exports, "__esModule", { value: true });
exports.MessagePrefix = exports.quaisymbol = void 0;
/**
 *  A constant for the ether symbol (normalized using NFKC).
 *
 *  (**i.e.** ``"\\u039e"``)
 */
exports.quaisymbol = "\u039e"; // "\uD835\uDF63";
/**
 *  A constant for the [[link-eip-191]] personal message prefix.
 *
 *  (**i.e.** ``"\\x19Ethereum Signed Message:\\n"``)
 */
exports.MessagePrefix = "\x19Quai Signed Message:\n";
//# sourceMappingURL=strings.js.map