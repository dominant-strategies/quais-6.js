import { AbstractHDWallet, NeuteredAddressInfo } from './hdwallet.js';
import { HDNodeWallet } from './hdnodewallet.js';
import { QiTransactionRequest, Provider, TransactionResponse } from '../providers/index.js';
import { computeAddress } from '../address/index.js';
import { getBytes, hexlify } from '../utils/index.js';
import { TransactionLike, QiTransaction, TxInput } from '../transaction/index.js';
import { MuSigFactory } from '@brandonblack/musig';
import { schnorr } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { musigCrypto } from '../crypto/index.js';
import { Outpoint } from '../transaction/utxo.js';
import { getZoneForAddress } from '../utils/index.js';
import { AllowedCoinType, Zone } from '../constants/index.js';

type OutpointInfo = {
    outpoint: Outpoint;
    address: string;
    zone: Zone;
    account?: number;
};

export class QiHDWallet extends AbstractHDWallet {
    protected static _GAP_LIMIT: number = 20;

    protected static _coinType: AllowedCoinType = 969;

    // Map of change addresses to address info
    protected _changeAddresses: Map<string, NeuteredAddressInfo> = new Map();

    // Array of gap addresses
    protected _gapChangeAddresses: NeuteredAddressInfo[] = [];

    // Array of gap change addresses
    protected _gapAddresses: NeuteredAddressInfo[] = [];

    protected _outpoints: OutpointInfo[] = [];

    private constructor(root: HDNodeWallet, provider?: Provider) {
        super(root, provider);
    }

    public getNextChangeAddress(account: number, zone: Zone): NeuteredAddressInfo {
        this.validateZone(zone);
        if (!this._accounts.has(account)) {
            this.addAccount(account);
        }
        const filteredAccountInfos = Array.from(this._changeAddresses.values()).filter(
            (addressInfo) => addressInfo.account === account && addressInfo.zone === zone,
        );
        const lastIndex = filteredAccountInfos.reduce(
            (maxIndex, addressInfo) => Math.max(maxIndex, addressInfo.index),
            -1,
        );
        // call derive address with change = true
        const addressNode = this.deriveAddress(account, lastIndex + 1, zone, true);

        const neuteredAddressInfo = {
            pubKey: addressNode.publicKey,
            address: addressNode.address,
            account: account,
            index: addressNode.index,
            change: true,
            zone: zone,
        };

        this._changeAddresses.set(neuteredAddressInfo.address, neuteredAddressInfo);

        return neuteredAddressInfo;
    }

    public importOutpoints(outpoints: OutpointInfo[]): void {
        outpoints.forEach((outpoint) => {
            this.validateZone(outpoint.zone);
            this._outpoints.push(outpoint);
        });
    }

    public getOutpoints(zone: Zone): OutpointInfo[] {
        this.validateZone(zone);
        return this._outpoints.filter((outpoint) => outpoint.zone === zone);
    }

    /**
     * Signs a Qi transaction and returns the serialized transaction
     *
     * @param {QiTransactionRequest} tx - The transaction to sign.
     *
     * @returns {Promise<string>} The serialized transaction.
     * @throws {Error} If the UTXO transaction is invalid.
     */
    public async signTransaction(tx: QiTransactionRequest): Promise<string> {
        const txobj = QiTransaction.from(<TransactionLike>tx);
        if (!txobj.txInputs || txobj.txInputs.length == 0 || !txobj.txOutputs)
            throw new Error('Invalid UTXO transaction, missing inputs or outputs');

        const hash = keccak_256(txobj.unsignedSerialized);

        let signature: string;

        if (txobj.txInputs.length == 1) {
            signature = this.createSchnorrSignature(txobj.txInputs[0], hash);
        } else {
            signature = this.createMuSigSignature(txobj, hash);
        }

        txobj.signature = signature;
        return txobj.serialized;
    }

    public async sendTransaction(tx: QiTransactionRequest): Promise<TransactionResponse> {
        if (!this.provider) {
            throw new Error('Provider is not set');
        }
        if (!tx.inputs || tx.inputs.length === 0) {
            throw new Error('Transaction has no inputs');
        }
        const input = tx.inputs[0];
        const address = computeAddress(input.pubkey);
        const shard = getZoneForAddress(address);
        if (!shard) {
            throw new Error(`Address ${address} not found in any shard`);
        }

        // verify all inputs are from the same shard
        if (tx.inputs.some((input) => getZoneForAddress(computeAddress(input.pubkey)) !== shard)) {
            throw new Error('All inputs must be from the same shard');
        }

        const signedTx = await this.signTransaction(tx);

        return await this.provider.broadcastTransaction(shard, signedTx);
    }

    // createSchnorrSignature returns a schnorr signature for the given message and private key
    private createSchnorrSignature(input: TxInput, hash: Uint8Array): string {
        const privKey = this.derivePrivateKeyForInput(input);
        const signature = schnorr.sign(hash, getBytes(privKey));
        return hexlify(signature);
    }

    // createMuSigSignature returns a MuSig signature for the given message
    // and private keys corresponding to the input addresses
    private createMuSigSignature(tx: QiTransaction, hash: Uint8Array): string {
        const musig = MuSigFactory(musigCrypto);

        // Collect private keys corresponding to the pubkeys found on the inputs
        const privKeysSet = new Set<string>();
        tx.txInputs!.forEach((input) => {
            const privKey = this.derivePrivateKeyForInput(input);
            privKeysSet.add(privKey);
        });
        const privKeys = Array.from(privKeysSet);

        // Create an array of public keys corresponding to the private keys for musig aggregation
        const pubKeys: Uint8Array[] = privKeys
            .map((privKey) => musigCrypto.getPublicKey(getBytes(privKey!), true))
            .filter((pubKey) => pubKey !== null) as Uint8Array[];

        // Generate nonces for each public key
        const nonces = pubKeys.map((pk) => musig.nonceGen({ publicKey: getBytes(pk!) }));
        const aggNonce = musig.nonceAgg(nonces);

        const signingSession = musig.startSigningSession(aggNonce, hash, pubKeys);

        // Create partial signatures for each private key
        const partialSignatures = privKeys.map((sk, index) =>
            musig.partialSign({
                secretKey: getBytes(sk || ''),
                publicNonce: nonces[index],
                sessionKey: signingSession,
                verify: true,
            }),
        );

        // Aggregate the partial signatures into a final aggregated signature
        const finalSignature = musig.signAgg(partialSignatures, signingSession);

        return hexlify(finalSignature);
    }

    // Helper method that returns the private key for the public key
    private derivePrivateKeyForInput(input: TxInput): string {
        if (!input.pubkey) throw new Error('Missing public key for input');
        const address = computeAddress(input.pubkey);
        // get address info
        const addressInfo = this.getAddressInfo(address);
        if (!addressInfo) throw new Error(`Address not found: ${address}`);
        // derive an HDNode for the address and get the private key
        const accountNode = this._accounts.get(addressInfo.account);
        if (!accountNode) {
            throw new Error(`Account ${addressInfo.account} not found for address ${address}`);
        }
        const changeNode = accountNode.deriveChild(0);
        const addressNode = changeNode.deriveChild(addressInfo.index);
        return addressNode.privateKey;
    }

    // scan scans the specified zone for addresses with unspent outputs.
    // Starting at index 0, tt will generate new addresses until
    // the gap limit is reached for both gap and change addresses.
    public async scan(zone: Zone, account: number = 0): Promise<void> {
        this.validateZone(zone);
        // flush the existing addresses and outpoints
        this._addresses = new Map();
        this._changeAddresses = new Map();
        this._gapAddresses = [];
        this._gapChangeAddresses = [];
        this._outpoints = [];

        await this._scan(zone, account);
    }

    // sync scans the specified zone for addresses with unspent outputs.
    // Starting at the last address index, it will generate new addresses until
    // the gap limit is reached for both gap and change addresses.
    // If no account is specified, it will scan all accounts known to the wallet
    public async sync(zone: Zone, account?: number): Promise<void> {
        this.validateZone(zone);
        if (account) {
            await this._scan(zone, account);
        } else {
            for (const account of this._accounts.keys()) {
                await this._scan(zone, account);
            }
        }
    }

    private async _scan(zone: Zone, account: number = 0): Promise<void> {
        if (!this.provider) throw new Error('Provider not set');

        if (!this._accounts.has(account)) {
            this.addAccount(account);
        }

        let gapAddressesCount = 0;
        let changeGapAddressesCount = 0;

        // helper function to handle the common logic for both gap and change addresses
        const handleAddressScanning = async (
            getAddressInfo: () => NeuteredAddressInfo,
            addressesCount: number,
            gapAddressesArray: NeuteredAddressInfo[],
        ): Promise<number> => {
            const addressInfo = getAddressInfo();
            const outpoints = await this.getOutpointsByAddress(addressInfo.address);
            if (outpoints.length === 0) {
                addressesCount++;
                gapAddressesArray.push(addressInfo);
            } else {
                addressesCount = 0;
                gapAddressesArray = [];
                const newOutpointsInfo = outpoints.map((outpoint) => ({
                    outpoint,
                    address: addressInfo.address,
                    zone: zone,
                }));
                this._outpoints.push(...newOutpointsInfo);
            }
            return addressesCount;
        };

        // main loop to scan addresses up to the gap limit
        while (gapAddressesCount < QiHDWallet._GAP_LIMIT || changeGapAddressesCount < QiHDWallet._GAP_LIMIT) {
            [gapAddressesCount, changeGapAddressesCount] = await Promise.all([
                gapAddressesCount < QiHDWallet._GAP_LIMIT
                    ? handleAddressScanning(
                          () => this.getNextAddress(account, zone),
                          gapAddressesCount,
                          this._gapAddresses,
                      )
                    : gapAddressesCount,

                changeGapAddressesCount < QiHDWallet._GAP_LIMIT
                    ? handleAddressScanning(
                          () => this.getNextChangeAddress(account, zone),
                          changeGapAddressesCount,
                          this._gapChangeAddresses,
                      )
                    : changeGapAddressesCount,
            ]);
        }
    }

    // getOutpointsByAddress queries the network node for the outpoints of the specified address
    private async getOutpointsByAddress(address: string): Promise<Outpoint[]> {
        try {
            const outpointsMap = await this.provider!.getOutpointsByAddress(address);
            if (!outpointsMap) {
                return [];
            }
            return Object.values(outpointsMap) as Outpoint[];
        } catch (error) {
            throw new Error(`Failed to get outpoints for address: ${address}`);
        }
    }

    public getChangeAddressesForZone(zone: Zone): NeuteredAddressInfo[] {
        this.validateZone(zone);
        const changeAddresses = this._changeAddresses.values();
        return Array.from(changeAddresses).filter((addressInfo) => addressInfo.zone === zone);
    }

    public getGapAddressesForZone(zone: Zone): NeuteredAddressInfo[] {
        this.validateZone(zone);
        const gapAddresses = this._gapAddresses.filter((addressInfo) => addressInfo.zone === zone);
        return gapAddresses;
    }

    public getGapChangeAddressesForZone(zone: Zone): NeuteredAddressInfo[] {
        this.validateZone(zone);
        const gapChangeAddresses = this._gapChangeAddresses.filter((addressInfo) => addressInfo.zone === zone);
        return gapChangeAddresses;
    }
}
