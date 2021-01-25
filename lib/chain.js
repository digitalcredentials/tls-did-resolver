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
exports.getSignature = exports.getChains = exports.getAttributes = exports.getExpiry = exports.getDomain = exports.getContracts = exports.REGISTRY = void 0;
var ethers_1 = require("ethers");
var TLSDID_json_1 = __importDefault(require("@digitalcredentials/tls-did-registry/build/contracts/TLSDID.json"));
var TLSDIDRegistry_json_1 = __importDefault(require("@digitalcredentials/tls-did-registry/build/contracts/TLSDIDRegistry.json"));
var utils_1 = require("./utils");
exports.REGISTRY = '0xA725A297b0F81c502df772DBE2D0AEb68788679d';
var NULL_ADDRESS = '0x0000000000000000000000000000000000000000';
/**
 * Gets all TLSDIDContracts associated with a TLS-DID as ethers contract objects
 *
 * @param {string} did - TLS DID
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Promise<Contract>}
 */
function getContracts(domain, provider, registryAddress) {
    return __awaiter(this, void 0, void 0, function () {
        var registry, addresses, contracts, _i, addresses_1, address;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    registry = new ethers_1.Contract(registryAddress, TLSDIDRegistry_json_1.default.abi, provider);
                    return [4 /*yield*/, registry.getContracts(domain)];
                case 1:
                    addresses = _a.sent();
                    contracts = [];
                    for (_i = 0, addresses_1 = addresses; _i < addresses_1.length; _i++) {
                        address = addresses_1[_i];
                        if (address == NULL_ADDRESS) {
                            //DID was deleted
                            continue;
                        }
                        //Create contract object from address.
                        contracts.push(new ethers_1.Contract(address, TLSDID_json_1.default.abi, provider));
                    }
                    return [2 /*return*/, contracts];
            }
        });
    });
}
exports.getContracts = getContracts;
/**
 * Gets domain from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<String>} - Domain
 */
function getDomain(contract) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, contract.domain()];
                case 1: return [2 /*return*/, _a.sent()];
            }
        });
    });
}
exports.getDomain = getDomain;
/**
 * Gets expiry from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<Date>} - Expiry
 */
function getExpiry(contract) {
    return __awaiter(this, void 0, void 0, function () {
        var expiryBN;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, contract.expiry()];
                case 1:
                    expiryBN = _a.sent();
                    return [2 /*return*/, new Date(expiryBN.toNumber())];
            }
        });
    });
}
exports.getExpiry = getExpiry;
/**
 * Gets attributes from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<Attribute[]>} - Attribute Array
 */
function getAttributes(contract) {
    return __awaiter(this, void 0, void 0, function () {
        var attributeCountBN, attributeCount, attributesStrings, attributes;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, contract.getAttributeCount()];
                case 1:
                    attributeCountBN = _a.sent();
                    attributeCount = attributeCountBN.toNumber();
                    return [4 /*yield*/, Promise.all(Array.from(Array(attributeCount).keys()).map(function (i) { return contract.getAttribute(i); }))];
                case 2:
                    attributesStrings = _a.sent();
                    attributes = [];
                    attributesStrings.forEach(function (attribute) {
                        var path = attribute['0'];
                        var value = attribute['1'];
                        attributes.push({ path: path, value: value });
                    });
                    return [2 /*return*/, attributes];
            }
        });
    });
}
exports.getAttributes = getAttributes;
/**
 * Gets chains from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<string[][]>} - Array of chain arrays
 */
function getChains(contract) {
    return __awaiter(this, void 0, void 0, function () {
        var chainCountBN, chainCount, chains;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, contract.getChainCount()];
                case 1:
                    chainCountBN = _a.sent();
                    chainCount = chainCountBN.toNumber();
                    return [4 /*yield*/, Promise.all(Array.from(Array(chainCount).keys()).map(function (i) { return contract.getChain(i); }))];
                case 2:
                    chains = _a.sent();
                    //Splits concatenated cert string to array of certs
                    return [2 /*return*/, chains.map(function (chain) { return utils_1.chainToCerts(chain); })];
            }
        });
    });
}
exports.getChains = getChains;
/**
 * Gets signature from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<string>} - Signature
 */
function getSignature(contract) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, contract.signature()];
                case 1: return [2 /*return*/, _a.sent()];
            }
        });
    });
}
exports.getSignature = getSignature;
//# sourceMappingURL=chain.js.map