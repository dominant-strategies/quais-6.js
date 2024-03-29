"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const assert_1 = tslib_1.__importDefault(require("assert"));
const index_js_1 = require("../index.js");
const utils_js_1 = require("./utils.js");
//import { dnsEncode, isValidName, namehash } from "../index.js";
describe("Tests Namehash", function () {
    const tests = (0, utils_js_1.loadTests)("namehash");
    for (const test of tests) {
        if (!test.error) {
            it(`hashes ENS name: ${JSON.stringify(test.name)}`, function () {
                const actual = (0, index_js_1.namehash)(test.ensName);
                assert_1.default.equal(actual, test.namehash, "namehash");
                // The empty string is not a valid ENS name
                if (test.ensName) {
                    assert_1.default.ok((0, index_js_1.isValidName)(test.ensName), "isValidName");
                }
            });
        }
    }
    for (const test of tests) {
        if (test.error) {
            it(`correctly fails to hash ENS name: ${test.error} ${JSON.stringify(test.name)}`, function () {
                assert_1.default.throws(function () {
                    const actual = (0, index_js_1.namehash)(test.ensName);
                    console.log("Failed to throw", actual);
                }, (error) => {
                    return ((0, index_js_1.isError)(error, "INVALID_ARGUMENT") &&
                        error.argument === "name" && error.value === test.ensName);
                });
                // The empty string is not a valid ENS name
                if (test.ensName) {
                    assert_1.default.ok(!(0, index_js_1.isValidName)(test.ensName), "!isValidName");
                }
            });
        }
    }
});
/*
describe("Tests Bad ENS Names", function() {
    const badTests: Array<{ ensName: any, prefix: string }> = [
        { ensName: ".", prefix: "missing component" },
        { ensName:"..", prefix: "missing component" },
        { ensName:"ricmoo..eth", prefix: "missing component" },
        { ensName:"ricmoo...eth", prefix: "missing component" },
        { ensName:".foo", prefix: "missing component" },
        { ensName:"foo.", prefix: "missing component" },
        { ensName: 1234, prefix: "not a string" },
        { ensName: true, prefix: "not a string" },
    ];

    // The empty string is not a valid name, but has a valid namehash
    // (the zero hash) as it is the base case for recursion
    it("empty ENS name", function() {
        assert.ok(!isValidName(""), "!isValidName");
    });

    for (const { ensName, prefix } of badTests) {
        it(`fails on bad ENS name: ${ JSON.stringify(ensName) }`, function() {
            assert.ok(!isValidName(ensName), "!isValidName");
            assert.throws(() => {
                const result = namehash(ensName);
                console.log(result);
            }, (error) => {
                const errorPrefix = `invalid ENS name; ${ prefix }`;
                return (error.code === "INVALID_ARGUMENT" &&
                    error.argument === "name" && error.value === ensName &&
                    error.message.substring(0, errorPrefix.length) === errorPrefix);
            });
        });
    }
});

describe("Tests DNS Encoding", function() {
    const tests: Array<{ ensName: string, dnsEncoded: string}> = [
        { ensName: "", dnsEncoded: "0x00" },
        { ensName: "ricmoo.eth", dnsEncoded: "0x067269636d6f6f0365746800" },
    ];

    for (const { ensName, dnsEncoded } of tests) {
        it(`computes the DNS Encoding: ${ JSON.stringify(ensName) }`, function() {
            assert.equal(dnsEncode(ensName), dnsEncoded, "dnsEncoded");
        });
    }
});

describe("Tests DNS Names", function() {
    const badTests: Array<{ ensName: any, prefix: string}> = [
        { ensName: ".", prefix: "invalid DNS name; missing component" },
        { ensName: "foo..bar", prefix: "invalid DNS name; missing component" },
        { ensName: ".foo", prefix: "invalid DNS name; missing component" },
        { ensName: "foo.", prefix: "invalid DNS name; missing component" },
        { ensName: 1234, prefix: "invalid DNS name; not a string" },
        { ensName: true, prefix: "invalid DNS name; not a string" },
    ];

    for (const { ensName, prefix } of badTests) {
        it(`fails on bad DNS name: ${ JSON.stringify(ensName) }`, function() {
            assert.throws(() => {
                const result = dnsEncode(ensName);
                console.log(result);
            }, (error) => {
                return (error.code === "INVALID_ARGUMENT" &&
                    error.argument === "name" && error.value === ensName &&
                    error.message.substring(0, prefix.length) === prefix);
            });
        });
    }

    {
        const ensName = "foobar012345678901234567890123456789012345678901234567890123456789";
        const prefix = "too long";
        it(`fails on bad DNS name: ${ JSON.stringify(ensName) }`, function() {
            assert.throws(() => {
                const result = dnsEncode(ensName);
                console.log(result);
            }, (error) => {
                return (error.code === "INVALID_ARGUMENT" &&
                    error.argument === "value" && error.value === ensName &&
                    error.message.substring(0, prefix.length) === prefix);
            });
        });
    }

});
*/
describe("Test EIP-191 Personal Message Hash", function () {
    const tests = [
        {
            test: "hello-world",
            message: "Hello World",
            hash: "0xca6464b285e602e01f3261caa151da2bd35fe19cb3532f7acd0d594ca0d810c5"
        },
        {
            test: "binary-message",
            message: new Uint8Array([0x42, 0x43]),
            hash: "0xd2ca8706bdbb1255b510b6acf42339faabf95bb8192cc7c562a6019ad8463c60"
        },
        {
            test: "hex-looking-string",
            message: "0x4243",
            hash: "0xcfe58e0f243f48080feeeb86f9b27e35f65955d3b39a644478c376b2733d9804"
        }
    ];
    for (const test of tests) {
        it(`tests hashMessage: ${test.test}`, function () {
            assert_1.default.equal((0, index_js_1.hashMessage)(test.message), test.hash);
        });
    }
});
describe("Test Solidity Hash functions", function () {
    const tests = (0, utils_js_1.loadTests)("solidity-hashes");
    for (const test of tests) {
        it(`computes the solidity keccak256: ${test.name}`, function () {
            assert_1.default.equal((0, index_js_1.solidityPackedKeccak256)(test.types, test.values), test.keccak256);
        });
    }
    for (const test of tests) {
        it(`computes the solidity sha256: ${test.name}`, function () {
            assert_1.default.equal((0, index_js_1.solidityPackedSha256)(test.types, test.values), test.sha256);
        });
    }
    const badTypes = [
        { types: ["uint5"], values: [1] },
        { types: ["bytes0"], values: ["0x"] },
        { types: ["blorb"], values: [false] },
    ];
    for (const { types, values } of badTypes) {
        it("correctly fails on invalid type", function () {
            assert_1.default.throws(function () {
                const result = (0, index_js_1.solidityPacked)(types, values);
                console.log(result);
            }, function (error) {
                return ((0, index_js_1.isError)(error, "INVALID_ARGUMENT") && error.argument === "type");
            });
        });
    }
});
//# sourceMappingURL=test-hash.js.map