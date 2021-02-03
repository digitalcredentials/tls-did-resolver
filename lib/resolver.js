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
Object.defineProperty(exports, "__esModule", { value: true });
exports.getResolver = void 0;
var tls_1 = require("tls");
var utils_1 = require("./utils");
var chain_1 = require("./chain");
/**
 * Resolves TLS DID
 *
 * @param {string} did - TLS DID
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Promise<Contract>}
 */
function processContracts(domain, contracts, rootCertificates) {
    return __awaiter(this, void 0, void 0, function () {
        var validContract, validChain, validAttributes, _i, contracts_1, contract, chains, validChains, contractDomain, expiry, now, attributes, signature, hash, valid;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _i = 0, contracts_1 = contracts;
                    _a.label = 1;
                case 1:
                    if (!(_i < contracts_1.length)) return [3 /*break*/, 9];
                    contract = contracts_1[_i];
                    return [4 /*yield*/, chain_1.getChains(contract)];
                case 2:
                    chains = _a.sent();
                    if (chains.length === 0) {
                        //No chain
                        return [3 /*break*/, 8];
                    }
                    return [4 /*yield*/, utils_1.verifyChains(chains, domain, rootCertificates)];
                case 3:
                    validChains = _a.sent();
                    if (validChains.length === 0) {
                        //No valid chain
                        return [3 /*break*/, 8];
                    }
                    return [4 /*yield*/, chain_1.getDomain(contract)];
                case 4:
                    contractDomain = _a.sent();
                    if (domain !== contractDomain) {
                        //DID domain and contract domain to not match
                        return [3 /*break*/, 8];
                    }
                    return [4 /*yield*/, chain_1.getExpiry(contract)];
                case 5:
                    expiry = _a.sent();
                    now = new Date();
                    if (expiry && expiry < now) {
                        //Contract expired
                        return [3 /*break*/, 8];
                    }
                    return [4 /*yield*/, chain_1.getAttributes(contract)];
                case 6:
                    attributes = _a.sent();
                    return [4 /*yield*/, chain_1.getSignature(contract)];
                case 7:
                    signature = _a.sent();
                    hash = utils_1.hashContract(domain, contract.address, attributes, expiry, chains);
                    valid = utils_1.verify(chains[0][0], signature, hash);
                    if (!valid) {
                        //Signatures does not match data
                        return [3 /*break*/, 8];
                    }
                    if (valid && !validContract) {
                        validContract = contract;
                        validChain = validChains[0];
                        validAttributes = attributes;
                    }
                    else if (valid) {
                        throw new Error(contracts.length + " contracts were found. Multiple were valid.");
                    }
                    _a.label = 8;
                case 8:
                    _i++;
                    return [3 /*break*/, 1];
                case 9:
                    //If single valid contract was found it is returned with its corresponding
                    //tls certification in jwk format
                    //If no valid contract was found an error is thrown
                    if (validContract) {
                        return [2 /*return*/, validAttributes];
                    }
                    else {
                        //TODO Check did-resolver on how to handle errors
                        throw new Error(contracts.length + " contracts were found. None was valid.");
                    }
                    return [2 /*return*/];
            }
        });
    });
}
/**
 * Builds DID document
 *
 * @param {string} did - TLS DID
 * @param {Attribute []} attributes - The attributes of the DID document
 *
 * @returns {DIDDocument}
 */
function buildDIDDocument(did, attributes) {
    //Set context and subject
    var didDocument = {
        '@context': 'https://www.w3.org/ns/did/v1',
        id: did,
        publicKey: [],
    };
    //Set attributes by appending attribute values to the DID Document object
    attributes.forEach(function (attribute) { return utils_1.addValueAtPath(didDocument, attribute.path, attribute.value); });
    return didDocument;
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
function resolveTlsDid(did, config, registryAddress, rootCertificates) {
    if (config === void 0) { config = {}; }
    if (registryAddress === void 0) { registryAddress = chain_1.REGISTRY; }
    if (rootCertificates === void 0) { rootCertificates = tls_1.rootCertificates; }
    return __awaiter(this, void 0, void 0, function () {
        var provider, domain, contracts, attributes;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    provider = utils_1.configureProvider(config);
                    domain = did.substring(8);
                    return [4 /*yield*/, chain_1.getContracts(domain, provider, registryAddress)];
                case 1:
                    contracts = _a.sent();
                    if (contracts.length === 0) {
                        throw new Error('No contract was found');
                    }
                    return [4 /*yield*/, processContracts(domain, contracts, rootCertificates)];
                case 2:
                    attributes = _a.sent();
                    return [2 /*return*/, buildDIDDocument(did, attributes)];
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
function getResolver(config, registryAddress, rootCertificates) {
    function resolve(did) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, resolveTlsDid(did, config, registryAddress, rootCertificates)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    }
    return { tls: resolve };
}
exports.getResolver = getResolver;
//# sourceMappingURL=resolver.js.map