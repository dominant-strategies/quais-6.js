import { ProtoTransaction } from "../transaction/abstract-transaction.js";
import { ProtoWorkObject } from "../transaction/work-object.js";
import * as Proto from "./ProtoBuf/proto_block.js"

export function decodeProtoTransaction(bytes: Uint8Array): ProtoTransaction {
    const tx = Proto.block.ProtoTransaction.deserialize(bytes);
    return tx.toObject() as ProtoTransaction;
}

export function decodeProtoWorkObject(bytes: Uint8Array): ProtoWorkObject {
    const wo = Proto.block.ProtoWorkObject.deserialize(bytes);
    return wo.toObject() as ProtoWorkObject;
}