// import from provider.ts instead of index.ts to prevent circular dep
// from quaiscanProvider
import { Block, Log, QuaiTransactionResponse, TransactionReceipt, TransactionResponse } from '../providers/provider.js';
import { defineProperties, EventPayload } from '../utils/index.js';

import type { EventFragment, Interface, Result } from '../abi/index.js';
import type { Listener } from '../utils/index.js';
import type { Provider } from '../providers/index.js';

import type { BaseContract } from './contract.js';
import type { ContractEventName } from './types.js';
import { Shard } from '../constants/index.js';

/**
 * An **EventLog** contains additional properties parsed from the {@link Log | **Log**}.
 *
 * @category Contract
 */
export class EventLog extends Log {
    /**
     * The Contract Interface.
     */
    readonly interface!: Interface;

    /**
     * The matching event.
     */
    readonly fragment!: EventFragment;

    /**
     * The parsed arguments passed to the event by `emit`.
     */
    readonly args!: Result;

    /**
     * @ignore
     */
    constructor(log: Log, iface: Interface, fragment: EventFragment) {
        super(log, log.provider);
        const args = iface.decodeEventLog(fragment, log.data, log.topics);
        defineProperties<EventLog>(this, { args, fragment, interface: iface });
    }

    /**
     * The name of the event.
     */
    get eventName(): string {
        return this.fragment.name;
    }

    /**
     * The signature of the event.
     */
    get eventSignature(): string {
        return this.fragment.format();
    }
}

/**
 * An **EventLog** contains additional properties parsed from the {@link Log | **Log**}.
 *
 * @category Contract
 */
export class UndecodedEventLog extends Log {
    /**
     * The error encounted when trying to decode the log.
     */
    readonly error!: Error;

    /**
     * @ignore
     */
    constructor(log: Log, error: Error) {
        super(log, log.provider);
        defineProperties<UndecodedEventLog>(this, { error });
    }
}

/**
 * A **ContractTransactionReceipt** includes the parsed logs from a {@link TransactionReceipt | **TransactionReceipt**}.
 *
 * @category Contract
 */
export class ContractTransactionReceipt extends TransactionReceipt {
    readonly #iface: Interface;

    /**
     * @ignore
     */
    constructor(iface: Interface, provider: Provider, tx: TransactionReceipt) {
        super(tx, provider);
        this.#iface = iface;
    }

    /**
     * The parsed logs for any {@link Log | **Log**} which has a matching event in the Contract ABI.
     */
    get logs(): Array<EventLog | Log> {
        return super.logs.map((log) => {
            const fragment = log.topics.length ? this.#iface.getEvent(log.topics[0]) : null;
            if (fragment) {
                try {
                    return new EventLog(log, this.#iface, fragment);
                } catch (error: any) {
                    return new UndecodedEventLog(log, error);
                }
            }

            return log;
        });
    }
}

/**
 * A **ContractTransactionResponse** will return a {@link ContractTransactionReceipt | **ContractTransactionReceipt**}
 * when waited on.
 *
 * @category Contract
 */
export class ContractTransactionResponse extends QuaiTransactionResponse {
    readonly #iface: Interface;

    /**
     * @ignore
     */
    constructor(iface: Interface, provider: Provider, tx: QuaiTransactionResponse) {
        super(tx, provider);
        this.#iface = iface;
    }

    /**
     * Resolves once this transaction has been mined and has `confirms` blocks including it (default: `1`) with an
     * optional `timeout`.
     *
     * This can resolve to `null` only if `confirms` is `0` and the transaction has not been mined, otherwise this will
     * wait until enough confirmations have completed.
     *
     * @param {number} confirms - The number of confirmations to wait for.
     *
     * @returns {Promise<ContractTransactionReceipt | null>} The transaction receipt, or `null` if `confirms` is `0`.
     */
    async wait(confirms?: number): Promise<null | ContractTransactionReceipt> {
        const receipt = await super.wait(confirms);
        if (receipt == null) {
            return null;
        }
        return new ContractTransactionReceipt(this.#iface, this.provider, receipt);
    }
}

/**
 * A **ContractUnknownEventPayload** is included as the last parameter to Contract Events when the event does not match
 * any events in the ABI.
 *
 * @category Contract
 */
export class ContractUnknownEventPayload extends EventPayload<ContractEventName> {
    /**
     * The log with no matching events.
     */
    readonly log!: Log;

    /**
     * @_event:
     */
    constructor(contract: BaseContract, listener: null | Listener, filter: ContractEventName, log: Log) {
        super(contract, listener, filter);
        defineProperties<ContractUnknownEventPayload>(this, { log });
    }

    /**
     * Resolves to the block the event occured in.
     *
     * @param {Shard} shard - The shard to get the block from.
     *
     * @returns {Promise<Block>} A promise resolving to the block the event occured in.
     */
    async getBlock(shard: Shard): Promise<Block> {
        return await this.log.getBlock(shard);
    }

    /**
     * Resolves to the transaction the event occured in.
     *
     * @returns {Promise<TransactionResponse>} A promise resolving to the transaction the event occured in.
     */
    async getTransaction(): Promise<TransactionResponse> {
        return await this.log.getTransaction();
    }

    /**
     * Resolves to the transaction receipt the event occured in.
     *
     * @returns {Promise<TransactionReceipt>} A promise resolving to the transaction receipt the event occured in.
     */
    async getTransactionReceipt(): Promise<TransactionReceipt> {
        return await this.log.getTransactionReceipt();
    }
}

/**
 * A **ContractEventPayload** is included as the last parameter to Contract Events when the event is known.
 *
 * @category Contract
 */
export class ContractEventPayload extends ContractUnknownEventPayload {
    /**
     * The matching event.
     */
    declare readonly fragment: EventFragment;

    /**
     * The log, with parsed properties.
     */
    declare readonly log: EventLog;

    /**
     * The parsed arguments passed to the event by `emit`.
     */
    declare readonly args: Result;

    /**
     * @ignore
     */
    constructor(
        contract: BaseContract,
        listener: null | Listener,
        filter: ContractEventName,
        fragment: EventFragment,
        _log: Log,
    ) {
        super(contract, listener, filter, new EventLog(_log, contract.interface, fragment));
        const args = contract.interface.decodeEventLog(fragment, this.log.data, this.log.topics);
        defineProperties<ContractEventPayload>(this, { args, fragment });
    }

    /**
     * The event name.
     */
    get eventName(): string {
        return this.fragment.name;
    }

    /**
     * The event signature.
     */
    get eventSignature(): string {
        return this.fragment.format();
    }
}
