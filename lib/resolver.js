"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getResolver = exports.REGISTRY = void 0;
var ethers_1 = require("ethers");
var TLSDID_json_1 = __importDefault(require("tls-did-registry/build/contracts/TLSDID.json"));
var TLSDIDRegistry_json_1 = __importDefault(require("tls-did-registry/build/contracts/TLSDIDRegistry.json"));
var utils_1 = require("./utils");
exports.REGISTRY = '0x33fD81799f172C8C932C9a3Fbc7dda9cdE26880A';
/**
 * Resolves TLS DID
 *
 * @param {string} did - TLS DID
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Promise<{ contract: Contract; jwk: JWKRSAKey }>}
 */
function resolveContract(did, provider, registryAddress) {
    return __awaiter(this, void 0, void 0, function () {
        var registry, domain, addresses, cert, validContract, _i, addresses_1, address, contract, valid, jwk;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    registry = new ethers_1.Contract(registryAddress, TLSDIDRegistry_json_1.default.abi, provider);
                    domain = did.substring(8);
                    return [4 /*yield*/, registry.getContracts(domain)];
                case 1:
                    addresses = _a.sent();
                    if (addresses.length === 0) {
                        throw new Error('No contract was found');
                    }
                    cert = utils_1.debugCert();
                    _i = 0, addresses_1 = addresses;
                    _a.label = 2;
                case 2:
                    if (!(_i < addresses_1.length)) return [3 /*break*/, 5];
                    address = addresses_1[_i];
                    contract = new ethers_1.Contract(address, TLSDID_json_1.default.abi, provider);
                    return [4 /*yield*/, verifyContract(contract, did, cert)];
                case 3:
                    valid = _a.sent();
                    if (valid && !validContract) {
                        validContract = contract;
                    }
                    else if (valid) {
                        throw new Error(addresses.length + " contracts were found. Multiple were valid.");
                    }
                    _a.label = 4;
                case 4:
                    _i++;
                    return [3 /*break*/, 2];
                case 5:
                    //If single valid contract was found it is returned with its corresponding
                    //tls certification in jwk format
                    //If no valid contract was found an error is thrown
                    if (validContract) {
                        jwk = utils_1.x509ToJwk(cert);
                        return [2 /*return*/, { contract: validContract, jwk: jwk }];
                    }
                    else {
                        //TODO Check did-resolver on how to handle errors
                        throw new Error(addresses.length + " contracts were found. None was valid.");
                    }
                    return [2 /*return*/];
            }
        });
    });
}
/**
 * Verifies if TLS DID Contract signature is correct
 *
 * @param {ethers.Contract} contract - Ethers contract object
 * @param {string} did - TLS DID
 * @param {string} cert - Public pem certificate
 */
function verifyContract(contract, did, cert) {
    return __awaiter(this, void 0, void 0, function () {
        var signature, didDomain, contractDomain, attributes, attributeCountBN, attributeCount, i, attribute, path, value, expiryBN, expiry, now, hash, valid;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, contract.signature()];
                case 1:
                    signature = _a.sent();
                    didDomain = did.substring(8);
                    return [4 /*yield*/, contract.domain()];
                case 2:
                    contractDomain = _a.sent();
                    if (didDomain !== contractDomain) {
                        return [2 /*return*/, false];
                    }
                    attributes = [];
                    return [4 /*yield*/, contract.getAttributeCount()];
                case 3:
                    attributeCountBN = _a.sent();
                    attributeCount = attributeCountBN.toNumber();
                    i = 0;
                    _a.label = 4;
                case 4:
                    if (!(i < attributeCount)) return [3 /*break*/, 7];
                    return [4 /*yield*/, contract.getAttribute(i)];
                case 5:
                    attribute = _a.sent();
                    path = attribute['0'];
                    value = attribute['1'];
                    attributes.push({ path: path, value: value });
                    _a.label = 6;
                case 6:
                    i++;
                    return [3 /*break*/, 4];
                case 7: return [4 /*yield*/, contract.expiry()];
                case 8:
                    expiryBN = _a.sent();
                    expiry = new Date(expiryBN.toNumber());
                    now = new Date();
                    if (expiry && expiry < now) {
                        return [2 /*return*/, false];
                    }
                    hash = utils_1.hashContract(didDomain, contract.address, attributes, expiry);
                    valid = utils_1.verify(cert, signature, hash);
                    return [2 /*return*/, valid];
            }
        });
    });
}
/**
 * Resolves TLS DID
 *
 * @param {string} did - TLS DID
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Promise<DIDDocumentObject>}
 */
function resolveTlsDid(did, config, registryAddress) {
    if (config === void 0) { config = {}; }
    if (registryAddress === void 0) { registryAddress = exports.REGISTRY; }
    return __awaiter(this, void 0, void 0, function () {
        var provider, _a, contract, jwk, didDocument, attributeCount, i, attribute, path, value;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    provider = utils_1.configureProvider(config);
                    return [4 /*yield*/, resolveContract(did, provider, registryAddress)];
                case 1:
                    _a = _b.sent(), contract = _a.contract, jwk = _a.jwk;
                    didDocument = {
                        '@context': 'https://www.w3.org/ns/did/v1',
                        id: did,
                    };
                    //Set verification method based on JWK representation of tls pem certificate
                    didDocument['verificationMethod'] = [
                        {
                            id: did + "#keys-1",
                            type: 'JsonWebKey2020',
                            controller: did,
                            publicKeyJwk: jwk,
                        },
                    ];
                    return [4 /*yield*/, contract.getAttributeCount()];
                case 2:
                    attributeCount = _b.sent();
                    i = 0;
                    _b.label = 3;
                case 3:
                    if (!(i < attributeCount)) return [3 /*break*/, 6];
                    return [4 /*yield*/, contract.getAttribute(i)];
                case 4:
                    attribute = _b.sent();
                    path = attribute['0'];
                    value = attribute['1'];
                    utils_1.addValueAtPath(didDocument, path, value);
                    _b.label = 5;
                case 5:
                    i++;
                    return [3 /*break*/, 3];
                case 6: return [2 /*return*/, didDocument];
            }
        });
    });
}
/**
 * Gets TLS DID Resolver
 *
 * @param {ProviderConfig} config - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Resolver}
 */
function getResolver(config, registryAddress) {
    function resolve(did) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, resolveTlsDid(did, config, registryAddress)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    }
    return { tls: resolve };
}
exports.getResolver = getResolver;
//# sourceMappingURL=resolver.js.map