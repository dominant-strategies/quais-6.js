import { hexlify } from "./data";
import * as Proto from "./ProtoBuf/proto-block";
export function encodeProtoTransaction(object) {
    const tx = Proto.block.ProtoWorkObject.fromObject(object);
    return hexlify(tx.serialize());
}
export function encodeProtoWorkObject(object) {
    console.log("pre encoded work object", object);
    const wo = Proto.block.ProtoWorkObject.fromObject(object);
    return hexlify(wo.serialize());
}
//# sourceMappingURL=proto-encode.js.map