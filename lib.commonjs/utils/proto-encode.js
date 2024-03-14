"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.encodeProtoWorkObject = exports.encodeProtoTransaction = void 0;
const tslib_1 = require("tslib");
const data_1 = require("./data");
const Proto = tslib_1.__importStar(require("./ProtoBuf/proto-block"));
function encodeProtoTransaction(object) {
    const tx = Proto.block.ProtoWorkObject.fromObject(object);
    return (0, data_1.hexlify)(tx.serialize());
}
exports.encodeProtoTransaction = encodeProtoTransaction;
function encodeProtoWorkObject(object) {
    console.log("pre encoded work object", object);
    const wo = Proto.block.ProtoWorkObject.fromObject(object);
    return (0, data_1.hexlify)(wo.serialize());
}
exports.encodeProtoWorkObject = encodeProtoWorkObject;
//# sourceMappingURL=proto-encode.js.map