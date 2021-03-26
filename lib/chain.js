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
var __read = (this && this.__read) || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
};
var __spreadArray = (this && this.__spreadArray) || function (to, from) {
    for (var i = 0, il = from.length, j = to.length; i < il; i++, j++)
        to[j] = from[i];
    return to;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveClaimant = exports.getClaimants = exports.newRegistry = void 0;
var ethers_1 = require("ethers");
var utils_1 = require("ethers/lib/utils");
var TLSDIDRegistry_json_1 = __importDefault(require("@digitalcredentials/tls-did-registry/build/contracts/TLSDIDRegistry.json"));
/**
 * Creates TLS-DID registry contract object
 *
 * @param {providers.Provider} provider - Ethereum provider
 * @param {string} registryAddress - Ethereum address of TLS-DID registry contract
 *
 * @returns {Promise<Contract>}
 */
function newRegistry(provider, registryAddress) {
    return __awaiter(this, void 0, void 0, function () {
        var registry;
        return __generator(this, function (_a) {
            registry = new ethers_1.Contract(registryAddress, TLSDIDRegistry_json_1.default.abi, provider);
            return [2 /*return*/, registry];
        });
    });
}
exports.newRegistry = newRegistry;
/**
 * Reads claimants from TLS-DID registry contract
 *
 * @param {Contract} registry - Creates TLS-DID registry contract object
 * @param {string} domain - TLS-DID identifier (domain)
 *
 * @returns {Promise<string[]>}
 */
function getClaimants(registry, domain) {
    return __awaiter(this, void 0, void 0, function () {
        var claimantsCountBN, claimantsCount, claimants, uniqClaimants;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, registry.getClaimantsCount(domain)];
                case 1:
                    claimantsCountBN = _a.sent();
                    claimantsCount = claimantsCountBN.toNumber();
                    if (claimantsCount === 0) {
                        return [2 /*return*/, []];
                    }
                    return [4 /*yield*/, Promise.all(Array.from(Array(claimantsCount).keys()).map(function (i) { return registry.claimantsRegistry(domain, i); }))];
                case 2:
                    claimants = _a.sent();
                    uniqClaimants = Array.from(new Set(claimants));
                    return [2 /*return*/, uniqClaimants];
            }
        });
    });
}
exports.getClaimants = getClaimants;
/**
 * Queries events from ethereum chain for a claimant
 *
 * @param {Contract} registry - TLS-DID registry contract object
 * @param {string} domain - TLS-DID identifier (domain)
 * @param {string} address - Ethereum address of claimant
 *
 * @returns {Promise<Event[]>}
 */
function resolveClaimant(registry, domain, address) {
    return __awaiter(this, void 0, void 0, function () {
        var lastChangeBlockBN, lastChangeBlock, filters;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, registry.changeRegistry(address, domain)];
                case 1:
                    lastChangeBlockBN = _a.sent();
                    lastChangeBlock = lastChangeBlockBN.toNumber();
                    if (lastChangeBlock === 0) {
                        return [2 /*return*/, []];
                    }
                    filters = [
                        registry.filters.ExpiryChanged(),
                        registry.filters.SignatureChanged(),
                        registry.filters.AttributeChanged(),
                        registry.filters.ChainChanged(),
                    ];
                    filters.forEach(function (filter) { return filter.topics.push(utils_1.hexZeroPad(address, 32)); });
                    return [4 /*yield*/, queryChain(registry, filters, lastChangeBlock)];
                case 2: return [2 /*return*/, _a.sent()];
            }
        });
    });
}
exports.resolveClaimant = resolveClaimant;
/**
 * Queries events from ethereum chain for set of filters starting at block number
 *
 * @param {Contract} registry - TLS-DID registry contract object
 * @param {EventFilter[]} filters - Set of event filters
 * @param {number} block - Block number where the query is started
 *
 * @returns {Promise<Event[]>}
 */
function queryChain(registry, filters, block) {
    return __awaiter(this, void 0, void 0, function () {
        var events, previousChangeBlockBN, previousChangeBlock, _a, _b, _c, _d;
        return __generator(this, function (_e) {
            switch (_e.label) {
                case 0: return [4 /*yield*/, queryBlock(registry, filters, block)];
                case 1:
                    events = _e.sent();
                    if (events.length === 0) {
                        throw new Error("No event found in block: " + block);
                    }
                    previousChangeBlockBN = events[events.length - 1].args.previousChange;
                    previousChangeBlock = previousChangeBlockBN.toNumber();
                    if (!(previousChangeBlock > 0)) return [3 /*break*/, 3];
                    _b = (_a = events.push).apply;
                    _c = [events];
                    _d = [[]];
                    return [4 /*yield*/, queryChain(registry, filters, previousChangeBlock)];
                case 2:
                    _b.apply(_a, _c.concat([__spreadArray.apply(void 0, _d.concat([__read.apply(void 0, [(_e.sent())])]))]));
                    _e.label = 3;
                case 3: return [2 /*return*/, events];
            }
        });
    });
}
/**
 * Queries events from ethereum chain in block
 *
 * @param {Contract} registry - TLS-DID registry contract object
 * @param {EventFilter[]} filters - Set of event filters
 * @param {number} block - Block number where to query
 *
 * @returns {Promise<Event[]>}
 */
function queryBlock(registry, filters, block) {
    return __awaiter(this, void 0, void 0, function () {
        var events;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, Promise.all(filters.map(function (filter) { return registry.queryFilter(filter, block, block); }))];
                case 1:
                    events = (_a.sent()).flat();
                    return [2 /*return*/, events];
            }
        });
    });
}
//# sourceMappingURL=chain.js.map