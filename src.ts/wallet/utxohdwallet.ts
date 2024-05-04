
import { N, ShardData } from '../constants';
import { SigningKey, keccak256 as addressKeccak256 } from "../crypto/index.js";
import {
    BytesLike,
    Numeric,
    Provider,
    TransactionLike,
    Wordlist,
    assertArgument,
    assertPrivate,
    computeHmac,
    dataSlice,
    defineProperties,
    getBytes,
    getNumber,
    getShardForAddress,
    hexlify,
    isBytesLike,
    isUTXOAddress,
    randomBytes,
    ripemd160,
    sha256,
    toBeHex,
    toBigInt,
    computeAddress
} from '../quais.js';
import { Mnemonic } from './mnemonic.js';
import { HardenedBit, derivePath, ser_I } from './utils.js';
import { BaseWallet } from "./base-wallet.js";
import { MuSigFactory } from "@brandonblack/musig"
import { nobleCrypto } from "./musig-crypto.js";
import { schnorr } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { QiTransaction } from '../transaction/qi-transaction.js';
import { QiTransactionRequest } from '../providers/provider.js';
import { TxInput } from "../transaction/utxo.js";
import { getAddress } from "../address/index.js";

type UTXOAddress = {
    address: string;
    privKey: string;
}

type Outpoint = {
    Txhash: string;
    Index: number;
    Denomination: number;
};

type ShardWalletData = {
    addresses: UTXOAddress[];
    outpoints: Map<string, Outpoint[]>;
}

const MasterSecret = new Uint8Array([ 66, 105, 116, 99, 111, 105, 110, 32, 115, 101, 101, 100 ]);
const _guard = { };

export class UTXOHDWallet extends BaseWallet {
     /**
     *  The compressed public key.
     */
     readonly #publicKey!: string;

     /**
      *  The fingerprint.
      *
      *  A fingerprint allows quick qay to detect parent and child nodes,
      *  but developers should be prepared to deal with collisions as it
      *  is only 4 bytes.
      */
     readonly fingerprint!: string;
 
     /**
      *  The parent fingerprint.
      */
     readonly accountFingerprint!: string;
 
     /**
      *  The mnemonic used to create this HD Node, if available.
      *
      *  Sources such as extended keys do not encode the mnemonic, in
      *  which case this will be ``null``.
      */
     readonly mnemonic!: null | Mnemonic;
 
     /**
      *  The chaincode, which is effectively a public key used
      *  to derive children.
      */
     readonly chainCode!: string;
 
     /**
      *  The derivation path of this wallet.
      *
      *  Since extended keys do not provider full path details, this
      *  may be ``null``, if instantiated from a source that does not
      *  enocde it.
      */
     readonly path!: null | string;
 
     /**
      *  The child index of this wallet. Values over ``2 *\* 31`` indicate
      *  the node is hardened.
      */
     readonly index!: number;
 
     /**
      *  The depth of this wallet, which is the number of components
      *  in its path.
      */
     readonly depth!: number;

     coinType?: number;

    /**
     * Map of shard names to shardWalletData
     * shardWalletData contains the addresses and outpoints for the shard
     */
    #shardWallets: Map<string, ShardWalletData> = new Map();

    get shardWallets(): Map<string, ShardWalletData> {
        return this.#shardWallets;
    }

    set shardWallets(shardWallets: Map<string, ShardWalletData>) {
        this.#shardWallets = shardWallets;
    }
    
    // contains the last BIP44 index derived by the wallet (-1 if none have been derived yet)
    #lastDerivedAddressIndex: number = -1;

    /**
     * Gets the current publicKey
     */
    get publicKey(): string {
        return this.#publicKey;
    }
    /**
     *  @private
     */
    constructor(guard: any, signingKey: SigningKey, accountFingerprint: string, chainCode: string, path: null | string, index: number, depth: number, mnemonic: null | Mnemonic, provider: null | Provider) {
        super(signingKey, provider);
        assertPrivate(guard, _guard);

        this.#publicKey = signingKey.compressedPublicKey 

        const fingerprint = dataSlice(ripemd160(sha256(this.#publicKey)), 0, 4);
        defineProperties<UTXOHDWallet>(this, {
            accountFingerprint, fingerprint,
            chainCode, path, index, depth
        });
        defineProperties<UTXOHDWallet>(this, { mnemonic });
    }
    
    connect(provider: null | Provider): UTXOHDWallet {
        return new UTXOHDWallet(_guard, this.signingKey, this.accountFingerprint,
            this.chainCode, this.path, this.index, this.depth, this.mnemonic, provider);
    }

    derivePath(path: string): UTXOHDWallet {
        return derivePath<UTXOHDWallet>(this, path);
    }
    
    static #fromSeed(_seed: BytesLike, mnemonic: null | Mnemonic): UTXOHDWallet {
        assertArgument(isBytesLike(_seed), "invalid seed", "seed", "[REDACTED]");

        const seed = getBytes(_seed, "seed");
        assertArgument(seed.length >= 16 && seed.length <= 64 , "invalid seed", "seed", "[REDACTED]");

        const I = getBytes(computeHmac("sha512", MasterSecret, seed));
        const signingKey = new SigningKey(hexlify(I.slice(0, 32)));

        const result = new UTXOHDWallet(_guard, signingKey, "0x00000000", hexlify(I.slice(32)),
            "m", 0, 0, mnemonic, null);
        return result;
    }
    
    setCoinType(): void {
        this.coinType = Number(this.path?.split("/")[2].replace("'", ""));
    }

    /**
     *  Creates a new random HDNode.
     */
    static createRandom( path: string, password?: string, wordlist?: Wordlist): UTXOHDWallet {
        if (path == null || !this.isValidPath(path)) { throw new Error('Invalid path: ' + path)}
        const mnemonic = Mnemonic.fromEntropy(randomBytes(16), password, wordlist)
        return UTXOHDWallet.#fromSeed(mnemonic.computeSeed(), mnemonic).derivePath(path);
    }

    /**
     *  Create an HD Node from %%mnemonic%%.
     */
    static fromMnemonic(mnemonic: Mnemonic, path: string): UTXOHDWallet {
        if (path == null || !this.isValidPath(path)) { throw new Error('Invalid path: ' + path)}
        return UTXOHDWallet.#fromSeed(mnemonic.computeSeed(), mnemonic).derivePath(path);
    }

    /**
     *  Creates an HD Node from a mnemonic %%phrase%%.
     */
    static fromPhrase(phrase: string, path: string, password?: string, wordlist?: Wordlist): UTXOHDWallet {
        if (path == null || !this.isValidPath(path)) { throw new Error('Invalid path: ' + path)}
        const mnemonic = Mnemonic.fromPhrase(phrase, password, wordlist)
        return UTXOHDWallet.#fromSeed(mnemonic.computeSeed(), mnemonic).derivePath(path);
    }

    /**
     * Checks if the provided BIP44 path is valid and limited to the change level.
     * @param path The BIP44 path to check.
     * @returns true if the path is valid and does not include the address_index; false otherwise.
     */
    static isValidPath(path: string): boolean {
        // BIP44 path regex pattern for up to the 'change' level, excluding 'address_index'
        // This pattern matches paths like "m/44'/0'/0'/0" and "m/44'/60'/0'/1", but not "m/44'/60'/0'/0/0"
        const pathRegex = /^m\/44'\/\d+'\/\d+'\/[01]$/;
        return pathRegex.test(path);
    }

    /**
     *  Return the child for %%index%%.
     */
    deriveChild(_index: Numeric): UTXOHDWallet {
        const index = getNumber(_index, "index");
        assertArgument(index <= 0xffffffff, "invalid index", "index", index);

        // Base path
        let newDepth = this.depth + 1;
        let path = this.path;
        if (path) {
            let pathFields = path.split("/");
            if (pathFields.length == 6){
                pathFields.pop();
                path = pathFields.join("/");
                newDepth--;
            }

            path += "/" + (index & ~HardenedBit);
            if (index & HardenedBit) { path += "'"; }
        }
        const { IR, IL } = ser_I(index, this.chainCode, this.#publicKey, this.privateKey);
        const ki = new SigningKey(toBeHex((toBigInt(IL) + BigInt(this.privateKey)) % N, 32));
        
        //BIP44 if we are at the account depth get that fingerprint, otherwise continue with the current one
        let newFingerprint = this.depth == 3 ? this.fingerprint : this.accountFingerprint;

        return new UTXOHDWallet(_guard, ki, newFingerprint, hexlify(IR),
            path, index, newDepth, this.mnemonic, this.provider);

    }

        
    /**
     *  Generates a list of addresses and private keys with UTXOs in the specified zone
     *  It also updates the map of addresses to unspent outputs
     */
    async syncUTXOs(zone: string, gap: number = 20  ){
        zone = zone.toLowerCase();
        // Check if zone is valid
        const shard = ShardData.find(shard => shard.name.toLowerCase() === zone || shard.nickname.toLowerCase() === zone || shard.byte.toLowerCase() === zone);
        if (!shard) {
            throw new Error("Invalid zone");
        }
        /* 
        generate addresses by incrementing address index in bip44 
        check each address for utxos and add to utxoAddresses
        until we have had gap limit number of addresses with no utxos
        */
        const currentUtxoAddresses: UTXOAddress[] = [];
        const currentAddressOutpoints: { [address: string]: Outpoint[] } = {};
        let empty = 0
        // let accIndex = 0
        let currentIndex = this.#lastDerivedAddressIndex + 1;

        while (empty < gap) {
            // start from the last derived address index
            if (currentIndex > this.#lastDerivedAddressIndex) {
                const wallet = this.deriveAddress(currentIndex, zone);
                const address = wallet.address;
                const privKey = wallet.privateKey;

                // save the derived address
                currentUtxoAddresses.push({ address, privKey });
                this.#lastDerivedAddressIndex = currentIndex;


                // Check if the address has any UTXOs
                try {
                    // if provider is not set, throw error
                    if (!this.provider) throw new Error("Provider not set");
                    const outpointsMap = await this.provider?.getOutpointsByAddress(address)
                    if (!outpointsMap) {
                        empty++;
                    } else {
                        // add the outpoints to the addressOutpoints map
                        const outpoints = Object.values(outpointsMap);
                        currentAddressOutpoints[address]= outpoints;
                        empty = 0; // Reset the gap counter
                    }

                } catch (error) {
                    throw new Error(`Error getting utxos for address ${address}: ${error}`)
                }
            }
            //increment addrIndex in bip44 always
            currentIndex++;
        }
        // add the addresses and outpoints to the shardWalletData
        const shardWalletData: ShardWalletData = {
            addresses: currentUtxoAddresses,
            outpoints: new Map(Object.entries(currentAddressOutpoints))
        };
        this.#shardWallets.set(shard.nickname, shardWalletData);
    }
        
    /**
     * Derives address by incrementing address_index according to BIP44
     */
    deriveAddress(index: number, zone?: string): UTXOHDWallet {
        if (!this.path) throw new Error("Missing Path");

        //Case for a non quai/qi wallet where zone is not needed
        if (!zone){
            return this.derivePath(this.path + "/" + index.toString());
        }
        zone = zone.toLowerCase();
        // Check if zone is valid
        const shard = ShardData.find(shard => shard.name.toLowerCase() === zone || shard.nickname.toLowerCase() === zone || shard.byte.toLowerCase() === zone);
        if (!shard) {
            throw new Error("Invalid zone");
        }


        let newWallet: UTXOHDWallet;
        let addrIndex: number = 0;
        let zoneIndex: number = index + 1;
        do {
            newWallet = this.derivePath(addrIndex.toString());
            if (getShardForAddress(newWallet.address) == shard && ((newWallet.coinType == 969) == isUTXOAddress(newWallet.address)))
            zoneIndex--;
            addrIndex++;
        } while ( zoneIndex > 0);

        return newWallet;   
    }
    /**
     *  Signs a UTXO transaction and returns the serialized transaction
     */

    async signTransaction(tx: QiTransactionRequest): Promise<string> {
        const txobj = QiTransaction.from((<TransactionLike>tx))
        if (!txobj.txInputs || txobj.txInputs.length == 0 || !txobj.txOutputs) throw new Error('Invalid UTXO transaction, missing inputs or outputs')
        
        const hash = keccak_256(txobj.unsignedSerialized)

        let signature: string;

        if (txobj.txInputs.length == 1){
            signature = this.createSchnorrSignature(txobj.txInputs[0], hash);
        } else {
            signature = this.createMuSigSignature(txobj, hash);

        }

        txobj.signature = signature;
        return txobj.serialized;
    }

    // createSchnorrSignature returns a schnorr signature for the given message and private key
    private createSchnorrSignature(input: TxInput, hash: Uint8Array): string {
        // get the private key that generates the address for the first input
        if (!input.pub_key) throw new Error('Missing public key for input');
        const pubKey = input.pub_key;
        const address = this.getAddressFromPubKey(hexlify(pubKey));
        // get shard from address
        const shard = getShardForAddress(address);
        if (!shard) throw new Error(`Invalid address: ${address}`);
        // get the wallet data corresponding to the shard
        const shardWalletData = this.#shardWallets.get(shard.nickname);
        if (!shardWalletData) throw new Error(`Missing wallet data for shard: ${shard.name}`);
        // get the private key corresponding to the address
        const privKey = shardWalletData.addresses.find(utxoAddr => utxoAddr.address === address)?.privKey;
        if (!privKey) throw new Error(`Missing private key for ${hexlify(pubKey)}`);
        // create the schnorr signature
        const signature = schnorr.sign(hash, getBytes(privKey) );
        return hexlify(signature);
    }

    // createMuSigSignature returns a MuSig signature for the given message
    // and private keys corresponding to the input addresses
    private createMuSigSignature(tx: QiTransaction, hash: Uint8Array): string {
        const musig = MuSigFactory(nobleCrypto);

        // Collect private keys corresponding to the addresses of the inputs
        const privKeysSet = new Set<string>();
        tx.txInputs!.forEach(input => {
            if (!input.pub_key) throw new Error('Missing public key for input');
            const address = computeAddress(hexlify(input.pub_key));

            // get shard from address
            const shard = getShardForAddress(address);
            if (!shard) throw new Error(`Invalid address: ${address}`);
            // get the wallet data corresponding to the shard
            const shardWalletData = this.#shardWallets.get(shard.nickname);
            if (!shardWalletData) throw new Error(`Missing wallet data for shard: ${shard.name, shard.nickname}`);

            const utxoAddrObj = shardWalletData.addresses.find(utxoAddr => utxoAddr.address === address);
            if (!utxoAddrObj) {
                throw new Error(`Private key not found for public key associated with address: ${address}`);
            }
            privKeysSet.add(utxoAddrObj.privKey);
        });
        const privKeys = Array.from(privKeysSet);

        // Create an array of public keys corresponding to the private keys for musig aggregation
        const pubKeys: Uint8Array[] = privKeys.map(privKey => nobleCrypto.getPublicKey(getBytes(privKey!), true)).filter(pubKey => pubKey !== null) as Uint8Array[];

        // Generate nonces for each public key
        const nonces = pubKeys.map(pk => musig.nonceGen({publicKey: getBytes(pk!)}));
        const aggNonce = musig.nonceAgg(nonces);

        const signingSession = musig.startSigningSession(
            aggNonce,
            hash,
            pubKeys
        );

        // Create partial signatures for each private key
        const partialSignatures = privKeys.map((sk, index) =>
            musig.partialSign({
                secretKey: getBytes(sk || ''),
                publicNonce: nonces[index],
                sessionKey: signingSession,
                verify: true
            })
        );

        // Aggregate the partial signatures into a final aggregated signature
        const finalSignature = musig.signAgg(partialSignatures, signingSession);
        
        return hexlify(finalSignature);
    }

    // getAddressFromPubKey returns the address corresponding to the given public key
    getAddressFromPubKey(pubkey: string): string {
        return getAddress(addressKeccak256("0x" + pubkey.substring(4)).substring(26))
    }
}