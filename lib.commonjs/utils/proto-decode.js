"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeProtoWorkObject = exports.decodeProtoTransaction = void 0;
const tslib_1 = require("tslib");
const Proto = tslib_1.__importStar(require("./ProtoBuf/proto-block"));
function decodeProtoTransaction(object) {
    const tx = Proto.block.ProtoTransaction.deserialize(object);
    return tx.toObject();
}
exports.decodeProtoTransaction = decodeProtoTransaction;
function decodeProtoWorkObject(object) {
    const wo = Proto.block.ProtoWorkObject.deserialize(object);
    return wo.toObject();
}
exports.decodeProtoWorkObject = decodeProtoWorkObject;
//# sourceMappingURL=proto-decode.js.map