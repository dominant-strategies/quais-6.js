"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const assert_1 = tslib_1.__importDefault(require("assert"));
const utils_js_1 = require("./utils.js");
const index_js_1 = require("../index.js");
describe("Test Private Key Wallet", function () {
    const tests = (0, utils_js_1.loadTests)("accounts");
    tests.forEach(({ name, privateKey, address }) => {
        it(`creates wallet: ${name}`, function () {
            const wallet = new index_js_1.Wallet(privateKey);
            assert_1.default.equal(wallet.privateKey, privateKey);
            assert_1.default.equal(wallet.address, address);
        });
    });
});
describe("Test Transaction Signing", function () {
    const tests = (0, utils_js_1.loadTests)("transactions");
    for (const test of tests) {
        if (!test.signedEip155) {
            continue;
        }
        it(`tests signing an EIP-155 transaction: ${test.name}`, async function () {
            const wallet = new index_js_1.Wallet(test.privateKey);
            const txData = Object.assign({}, test.transaction, { type: 0, accessList: [], maxFeePerGas: 0, maxPriorityFeePerGas: 0 });
            const signed = await wallet.signTransaction(txData);
            // let parsed = Transaction.from(signed);
            // // console.log('txData: ', JSON.stringify(parsed))
            // // console.log('EXPECTED: ', test.signedEip155)
            // // console.log("ACTUAL: ", signed)
            assert_1.default.equal(signed, test.signedEip155, "signedEip155");
        });
    }
});
describe("Test Message Signing (EIP-191)", function () {
});
describe("Test Typed-Data Signing (EIP-712)", function () {
    const tests = (0, utils_js_1.loadTests)("typed-data");
    for (const test of tests) {
        const { privateKey, signature } = test;
        if (privateKey == null || signature == null) {
            continue;
        }
        it(`tests signing typed-data: ${test.name}`, async function () {
            const wallet = new index_js_1.Wallet(privateKey);
            const sig = await wallet.signTypedData(test.domain, test.types, test.data);
            assert_1.default.equal(sig, signature, "signature");
        });
    }
});
describe("Test Wallet Encryption", function () {
    const password = "foobar";
    // Loop:
    //  1 : random wallet (uses HDNodeWallet under the hood)
    //  2 : Wallet using private key (uses Wallet explicitly)
    for (let i = 0; i < 2; i++) {
        let wallet = index_js_1.Wallet.createRandom("m/44'/994'/0'/0");
        it("encrypts a random wallet: sync", function () {
            this.timeout(30000);
            const json = wallet.encryptSync(password);
            const decrypted = index_js_1.Wallet.fromEncryptedJsonSync(json, password);
            assert_1.default.equal(decrypted.address, wallet.address, "address");
        });
        it("encrypts a random wallet: async", async function () {
            this.timeout(30000);
            const json = await wallet.encrypt(password);
            const decrypted = await index_js_1.Wallet.fromEncryptedJson(json, password);
            assert_1.default.equal(decrypted.address, wallet.address, "address");
        });
        wallet = new index_js_1.Wallet((0, index_js_1.hexlify)((0, index_js_1.randomBytes)(32)));
    }
});
//# sourceMappingURL=test-wallet.js.map