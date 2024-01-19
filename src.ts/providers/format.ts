/**
 *  @_ignore
 */
import { getAddress, getCreateAddress } from "../address/index.js";
import { Signature } from "../crypto/index.js"
import { accessListify } from "../transaction/index.js";
import {
    getBigInt, getNumber, hexlify, isHexString, zeroPadValue,
    assert, assertArgument
} from "../utils/index.js";

import type {
    BlockParams, LogParams,
    TransactionReceiptParams, TransactionResponseParams, EtxParams
} from "./formatting.js";


const BN_0 = BigInt(0);

export type FormatFunc = (value: any) => any;

export function allowNull(format: FormatFunc, nullValue?: any): FormatFunc {
    return (function(value: any) {
        if (value == null) { return nullValue; }
        return format(value);
    });
}

export function arrayOf(format: FormatFunc): FormatFunc {
    return ((array: any) => {
        if (!Array.isArray(array)) { throw new Error("not an array"); }
        return array.map((i) => format(i));
    });
}

// Requires an object which matches a fleet of other formatters
// Any FormatFunc may return `undefined` to have the value omitted
// from the result object. Calls preserve `this`.
export function object(format: Record<string, FormatFunc>, altNames?: Record<string, Array<string>>): FormatFunc {
    return ((value: any) => {
        const result: any = { };
        for (const key in format) {
            let srcKey = key;
            if (altNames && key in altNames && !(srcKey in value)) {
                for (const altKey of altNames[key]) {
                    if (altKey in value) {
                        srcKey = altKey;
                        break;
                    }
                }
            }

            try {
                const nv = format[key](value[srcKey]);
                if (nv !== undefined) { result[key] = nv; }
            } catch (error) {
                const message = (error instanceof Error) ? error.message: "not-an-error";
                assert(false, `invalid value for value.${ key } (${ message })`, "BAD_DATA", { value })
            }
        }
        return result;
    });
}

export function formatBoolean(value: any): boolean {
    switch (value) {
        case true: case "true":
            return true;
        case false: case "false":
            return false;
    }
    assertArgument(false, `invalid boolean; ${ JSON.stringify(value) }`, "value", value);
}

export function formatData(value: string): string {
    assertArgument(isHexString(value, true), "invalid data", "value", value);
    return value;
}

export function formatHash(value: any): string {
    assertArgument(isHexString(value, 32), "invalid hash", "value", value);
    return value;
}

export function formatUint256(value: any): string {
    if (!isHexString(value)) {
        throw new Error("invalid uint256");
    }
    return zeroPadValue(value, 32);
}

const _formatLog = object({
    address: getAddress,
    blockHash: formatHash,
    blockNumber: getNumber,
    data: formatData,
    index: getNumber,
    removed: allowNull(formatBoolean, false),
    topics: arrayOf(formatHash),
    transactionHash: formatHash,
    transactionIndex: getNumber,
}, {
    index: [ "logIndex" ]
});

export function formatLog(value: any): LogParams {
    return _formatLog(value);
}

const _formatBlock = object({
    hash: allowNull(formatHash),
    parentHash: arrayOf(formatHash),
    number: arrayOf(getNumber),

    timestamp: getNumber,
    nonce: allowNull(formatData),
    difficulty: getBigInt,

    gasLimit: getBigInt,
    gasUsed: getBigInt,

    miner: allowNull(getAddress),
    extraData: formatData,

    baseFeePerGas: allowNull(getBigInt),

    extRollupRoot: formatHash,
    // extTransactions: arrayOf(formatTransaction), 
    extTransactionsRoot: formatHash,
    // transactions:
    transactionsRoot: formatHash,
    manifestHash: arrayOf(formatHash), 
    location: formatData, 
    parentDeltaS: arrayOf(getBigInt), 
    parentEntropy: arrayOf(getBigInt), 
    order: getNumber, 
    subManifest: arrayOf(formatData), 
    totalEntropy: getBigInt, 
    mixHash: formatHash,
    receiptsRoot: formatHash,
    sha3Uncles: formatHash,
    size: getBigInt,
    stateRoot: formatHash,
    uncles: arrayOf(formatHash),
});

export function formatBlock(value: any): BlockParams {
    const result = _formatBlock(value);
    result.transactions = value.transactions.map((tx: string | TransactionResponseParams) => {
        if (typeof(tx) === "string") { return tx; }
        return formatTransactionResponse(tx);
    });
    result.extTransactions = value.extTransactions.map((tx: string | TransactionResponseParams) => {
        if (typeof(tx) === "string") { return tx; }
        return formatTransactionResponse(tx);
    });
    return result;
}

const _formatReceiptLog = object({
    transactionIndex: getNumber,
    blockNumber: getNumber,
    transactionHash: formatHash,
    address: getAddress,
    topics: arrayOf(formatHash),
    data: formatData,
    index: getNumber,
    blockHash: formatHash,
}, {
    index: [ "logIndex" ]
});

export function formatReceiptLog(value: any): LogParams {
    return _formatReceiptLog(value);
}

const _formatEtx = object({
    type: allowNull(getNumber, 0),
    nonce: getNumber,
    gasPrice: allowNull(getBigInt),
    maxPriorityFeePerGas: getBigInt,
    maxFeePerGas: getBigInt,
    gas: getBigInt,
    value: allowNull(getBigInt, BN_0),
    input: formatData,
    to: allowNull(getAddress, null),
    accessList: allowNull(accessListify, null),
    chainId: allowNull(getBigInt, null),
    from: allowNull(getAddress, null),
    hash: formatHash,
}, {
    from: [ "sender" ],
});

export function formatEtx(value: any): EtxParams {
    return _formatEtx(value);
}

const _formatTransactionReceipt = object({
    to: allowNull(getAddress, null),
    from: allowNull(getAddress, null),
    contractAddress: allowNull(getAddress, null),
    // should be allowNull(hash), but broken-EIP-658 support is handled in receipt
    index: getNumber,
    root: allowNull(hexlify),
    gasUsed: getBigInt,
    logsBloom: allowNull(formatData),
    blockHash: formatHash,
    hash: formatHash,
    logs: arrayOf(formatReceiptLog),
    blockNumber: getNumber,
    //confirmations: allowNull(getNumber, null),
    cumulativeGasUsed: getBigInt,
    effectiveGasPrice: allowNull(getBigInt),
    status: allowNull(getNumber),
    type: allowNull(getNumber, 0),
    etxs: arrayOf(formatEtx),
}, {
    hash: [ "transactionHash" ],
    index: [ "transactionIndex" ],
});

export function formatTransactionReceipt(value: any): TransactionReceiptParams {
    const result = _formatTransactionReceipt(value);
    return result;
}

export function formatTransactionResponse(value: any): TransactionResponseParams {

    // Some clients (TestRPC) do strange things like return 0x0 for the
    // 0 address; correct this to be a real address
    if (value.to && getBigInt(value.to) === BN_0) {
        value.to = "0x0000000000000000000000000000000000000000";
    }
    if (value.type === "0x1") value.from = value.sender

    const result = object({
        hash: formatHash,

        type: (value: any) => {
            if (value === "0x" || value == null) { return 0; }
            return getNumber(value);
        },
        accessList: allowNull(accessListify, null),

        blockHash: allowNull(formatHash, null),
        blockNumber: allowNull(getNumber, null),
        index: allowNull(getNumber, null),

        //confirmations: allowNull(getNumber, null),

        from: getAddress,

        maxPriorityFeePerGas: allowNull(getBigInt),
        maxFeePerGas: allowNull(getBigInt),

        gasLimit: getBigInt,
        to: allowNull(getAddress, null),
        value: getBigInt,
        nonce: getNumber, 

        creates: allowNull(getAddress, null),

        chainId: allowNull(getBigInt, null),

        etxGasLimit: allowNull(getBigInt, null),
        etxGasPrice: allowNull(getBigInt, null),
        etxGasTip: allowNull(getBigInt, null),
        etxData: allowNull(formatData, null),
        etxAccessList: allowNull(accessListify, null),
    }, {
        data: [ "input" ],
        gasLimit: [ "gas" ],
        index: [ "transactionIndex" ],
    })(value);

    // If to and creates are empty, populate the creates from the value
    if (result.to == null && result.creates == null) {
        result.creates = getCreateAddress(result);
    }

    if (result.type !== 2) {
        delete result.etxGasLimit;
        delete result.etxGasPrice;
        delete result.etxGasTip;
        delete result.etxData;
        delete result.etxAccessList;
    } else {
        //Needed due to go-quai api using both external as naming and etx as naming
        //External is for when creating an external transaction
        //Etx is for when reading an external transaction
        if (result.etxGasLimit == null && value.externalGasLimit!= null)
            result.etxGasLimit = value.externalGasLimit;
        if (result.etxGasPrice == null && value.externalGasPrice!= null) 
            result.etxGasPrice = value.externalGasPrice;
        if (result.etxGasTip == null && value.externalGasTip!= null)
            result.etxGasTip = value.externalGasTip;
        if (result.etxData == null && value.externalData!= null)
            result.etxData = value.externalData;
        if (result.etxAccessList == null && value.externalAccessList!= null)
            result.etxAccessList = value.externalAccessList;
    }

    // Add an access list to supported transaction types
    if ((value.type === 1 || value.type === 2) && value.accessList == null) {
        result.accessList = [ ];
    }

    // Compute the signature
    if (value.signature) {
        result.signature = Signature.from(value.signature);
    } else {
        result.signature = Signature.from(value);
    }

    // Some backends omit ChainId on legacy transactions, but we can compute it
    if (result.chainId == null) {
        const chainId = result.signature.legacyChainId;
        if (chainId != null) { result.chainId = chainId; }
    }


    // @TODO: check chainID
    /*
    if (value.chainId != null) {
        let chainId = value.chainId;

        if (isHexString(chainId)) {
            chainId = BigNumber.from(chainId).toNumber();
        }

        result.chainId = chainId;

    } else {
        let chainId = value.networkId;

        // geth-etc returns chainId
        if (chainId == null && result.v == null) {
            chainId = value.chainId;
        }

        if (isHexString(chainId)) {
            chainId = BigNumber.from(chainId).toNumber();
        }

        if (typeof(chainId) !== "number" && result.v != null) {
            chainId = (result.v - 35) / 2;
            if (chainId < 0) { chainId = 0; }
            chainId = parseInt(chainId);
        }

        if (typeof(chainId) !== "number") { chainId = 0; }

        result.chainId = chainId;
    }
    */

    // 0x0000... should actually be null
    if (result.blockHash && getBigInt(result.blockHash) === BN_0) {
        result.blockHash = null;
    }

    return result;
}
