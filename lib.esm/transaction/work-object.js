import { formatNumber } from "../providers/format";
import { Signature, assert, getBytes, getNumber } from "../quais";
import { encodeProtoWorkObject } from "../utils/proto-encode";
import { Transaction } from "./transaction";
/**
 *  Represents a WorkObject, which includes header, body, and transaction information.
 */
export class WorkObject {
    #woHeader;
    #woBody;
    #tx;
    /**
     *  Constructs a WorkObject instance.
     *
     *  @param woHeader The header information of the WorkObject.
     *  @param woBody The body information of the WorkObject.
     *  @param tx The transaction associated with the WorkObject.
     *  @param signature The signature of the transaction (optional).
     */
    constructor(woHeader, woBody, tx, signature) {
        this.#woHeader = woHeader;
        this.#woBody = woBody;
        this.#tx = Transaction.from(tx);
        // Set the signature on the transaction
        this.#tx.signature = (signature == null) ? null : Signature.from(signature);
    }
    /** Gets the header information of the WorkObject. */
    get woHeader() { return this.#woHeader; }
    set woHeader(value) { this.#woHeader = value; }
    /** Gets the body information of the WorkObject. */
    get woBody() { return this.#woBody; }
    set woBody(value) { this.#woBody = value; }
    /** Gets the transaction associated with the WorkObject. */
    get tx() { return this.#tx; }
    set tx(value) { this.#tx = Transaction.from(value); }
    /**
     *  Gets the serialized representation of the WorkObject.
     *  Throws an error if the WorkObject transaction is unsigned.
     */
    get serialized() {
        assert(this.#tx.signature != null, "cannot serialize unsigned work object; maybe you meant .unsignedSerialized", "UNSUPPORTED_OPERATION", { operation: ".serialized" });
        return this.#serialize();
    }
    /**
     *  Gets the pre-image of the WorkObject.
     *  The hash of this is the digest which needs to be signed to authorize this WorkObject.
     */
    get unsignedSerialized() {
        return this.#serialize();
    }
    /**
     *  Creates a WorkObject instance from a WorkObjectLike object.
     *
     *  @param data The WorkObjectLike object to create the WorkObject from.
     *  @returns A new WorkObject instance.
     */
    static from(data) {
        return new WorkObject(data.woHeader, data.woBody, data.tx);
    }
    /**
     *  Converts the WorkObject to a JSON-like object.
     *
     *  @returns The WorkObject as a WorkObjectLike object.
     */
    toJson() {
        return {
            woHeader: this.woHeader,
            woBody: this.woBody,
            tx: this.tx.toJSON(),
        };
    }
    /**
     *  Converts the WorkObject to its protobuf representation.
     *
     *  @returns The WorkObject as a ProtoWorkObject.
     */
    toProtobuf() {
        return {
            wo_header: {
                difficulty: getBytes(this.woHeader.wodifficulty),
                header_hash: { value: getBytes(this.woHeader.woheaderHash) },
                location: { value: new Uint8Array(this.woHeader.wolocation) },
                nonce: getNumber(this.woHeader.wononce),
                number: formatNumber(this.woHeader.wonumber, "number"),
                parent_hash: { value: getBytes(this.woHeader.woparentHash) },
                tx_hash: { value: getBytes(this.woHeader.wotxHash) },
            },
            wo_body: {
                ext_transactions: { transactions: this.woBody.extTransactions.map(tx => Transaction.from(tx).toProtobuf()) },
                header: {
                    base_fee: getBytes(this.woBody.header.baseFeePerGas),
                    coinbase: getBytes(this.woBody.header.miner),
                    difficulty: getBytes(this.woBody.header.difficulty),
                    evm_root: { value: getBytes(this.woBody.header.evmRoot) },
                    etx_hash: { value: getBytes(this.woBody.header.extTransactionsRoot) },
                    etx_rollup_hash: { value: getBytes(this.woBody.header.extRollupRoot) },
                    extra: getBytes(this.woBody.header.extraData),
                    gas_limit: getNumber(this.woBody.header.gasLimit),
                    gas_used: getNumber(this.woBody.header.gasUsed),
                    location: { value: getBytes(this.woBody.header.location) },
                    manifest_hash: this.woBody.header.manifestHash.map(h => ({ value: getBytes(h) })),
                    mix_hash: { value: getBytes(this.woBody.header.mixHash) },
                    nonce: getNumber(this.woBody.header.nonce),
                    number: this.woBody.header.number.map(n => formatNumber(n, "number")),
                    parent_delta_s: this.woBody.header.parentDeltaS.map(h => formatNumber(h, "parent_delta_s")),
                    parent_entropy: this.woBody.header.parentEntropy.map(h => formatNumber(h, "parent_entropy")),
                    parent_hash: this.woBody.header.parentHash.map(h => ({ value: getBytes(h) })),
                    receipt_hash: { value: getBytes(this.woBody.header.receiptsRoot) },
                    tx_hash: { value: getBytes(this.woBody.header.transactionsRoot) },
                    uncle_hash: { value: getBytes(this.woBody.header.sha3Uncles) },
                    utxo_root: { value: getBytes(this.woBody.header.utxoRoot) },
                },
                transactions: { transactions: this.woBody.transactions.map(tx => Transaction.from(tx).toProtobuf()) },
                uncles: { work_objects: this.woBody.uncles.map(uncle => WorkObject.from(uncle).toProtobuf()) },
                manifest: { manifest: this.woBody.manifest.map(m => ({ value: getBytes(m) })) },
            },
            tx: this.tx.toProtobuf(),
        };
    }
    /**
     *  Creates a clone of the current WorkObject.
     *
     *  @returns A new WorkObject instance that is a clone of the current instance.
     */
    clone() {
        return WorkObject.from(this);
    }
    /**
     *  Serializes the WorkObject to a string.
     *
     *  @returns The serialized string representation of the WorkObject.
     */
    #serialize() {
        return encodeProtoWorkObject(this.toProtobuf());
    }
}
//# sourceMappingURL=work-object.js.map