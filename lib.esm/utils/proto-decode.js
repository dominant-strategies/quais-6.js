import * as Proto from "./ProtoBuf/proto-block";
export function decodeProtoTransaction(object) {
    const tx = Proto.block.ProtoTransaction.deserialize(object);
    return tx.toObject();
}
export function decodeProtoWorkObject(object) {
    const wo = Proto.block.ProtoWorkObject.deserialize(object);
    return wo.toObject();
}
//# sourceMappingURL=proto-decode.js.map