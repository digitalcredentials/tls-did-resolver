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
var __values = (this && this.__values) || function(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.getResolver = void 0;
var tls_1 = require("tls");
var tls_did_utils_1 = require("@digitalcredentials/tls-did-utils");
var utils_1 = require("./utils");
var did_resolver_1 = require("did-resolver");
var chain_1 = require("./chain");
/**
 * Gets TLS DID Resolver
 *
 * @param {ProviderConfig} config - Ethereum provider
 * @param {string} registryAddress - Address of TLS-DID Registry
 * @param {string[]} rootCertificates - Trusted TLS root certificates
 *
 * @returns {Resolver}
 */
function getResolver(config, registryAddress, rootCertificates) {
    function resolve(did, parsed) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, resolveTlsDid(did, parsed ? parsed : did_resolver_1.parse(did), config, registryAddress, rootCertificates)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    }
    return { tls: resolve };
}
exports.getResolver = getResolver;
/**
 * Resolves TLS DID
 *
 * @param {string} did - TLS DID
 * @param {ParsedDID} parsed - Parsed DID
 * @param {ProviderConfig} config - Configuration for ethereum provider
 * @param {string} registryAddress - Address of TLS-DID Registry
 * @param {string[]} rootCertificates - Trusted TLS root certificates
 *
 * @returns {Promise<DIDDocumentObject>}
 */
function resolveTlsDid(did, parsed, config, registryAddress, rootCertificates) {
    if (config === void 0) { config = {}; }
    if (registryAddress === void 0) { registryAddress = tls_did_utils_1.REGISTRY; }
    if (rootCertificates === void 0) { rootCertificates = tls_1.rootCertificates; }
    return __awaiter(this, void 0, void 0, function () {
        var domain, provider, registry, claimants, attributes;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    domain = parsed.id;
                    if ((domain === null || domain === void 0 ? void 0 : domain.length) === 0) {
                        throw new Error("TLS-DID could not be validly resolved. No domain provided");
                    }
                    provider = tls_did_utils_1.configureProvider(config);
                    return [4 /*yield*/, chain_1.newRegistry(provider, registryAddress)];
                case 1:
                    registry = _a.sent();
                    return [4 /*yield*/, chain_1.getClaimants(registry, domain)];
                case 2:
                    claimants = _a.sent();
                    if (claimants.length === 0) {
                        throw new Error("did:tls:" + domain + " could not be validly resolved. No claimants could be found");
                    }
                    return [4 /*yield*/, resolveClaimants(rootCertificates, registry, domain, claimants)];
                case 3:
                    attributes = _a.sent();
                    return [2 /*return*/, buildDIDDocument(did, attributes)];
            }
        });
    });
}
/**
 * Resolves all claimants
 *
 * @param {string[]} rootCertificates - Trusted TLS root certificates
 * @param {Contract} registry - TLS-DID registry contract object
 * @param {string} domain - TLS-DID identifier (domain)
 * @param {string[]} claimants - Set of ethereum addresses claiming control over TLS-DID
 *
 * @returns {Promise<DIDDocumentObject>}
 */
function resolveClaimants(rootCertificates, registry, domain, claimants) {
    return __awaiter(this, void 0, void 0, function () {
        var caStore, validAttributes, docValid, errors, _a, _b, _c, i, claimant, events, error_1, attributes, e_1_1;
        var e_1, _d;
        return __generator(this, function (_e) {
            switch (_e.label) {
                case 0:
                    caStore = utils_1.createCaStore(rootCertificates);
                    validAttributes = [];
                    docValid = false;
                    errors = [];
                    _e.label = 1;
                case 1:
                    _e.trys.push([1, 9, 10, 11]);
                    _a = __values(claimants.entries()), _b = _a.next();
                    _e.label = 2;
                case 2:
                    if (!!_b.done) return [3 /*break*/, 8];
                    _c = __read(_b.value, 2), i = _c[0], claimant = _c[1];
                    events = void 0;
                    _e.label = 3;
                case 3:
                    _e.trys.push([3, 5, , 6]);
                    return [4 /*yield*/, chain_1.resolveClaimant(registry, domain, claimant)];
                case 4:
                    events = _e.sent();
                    return [3 /*break*/, 6];
                case 5:
                    error_1 = _e.sent();
                    errors[i] = { claimant: claimant, error: error_1 };
                    return [3 /*break*/, 7];
                case 6:
                    if (events.length === 0) {
                        //No change events found for claimant
                        errors[i] = { claimant: claimant, error: new Error('No events') };
                        return [3 /*break*/, 7];
                    }
                    attributes = void 0;
                    try {
                        attributes = processEvents(events, domain, caStore);
                    }
                    catch (error) {
                        errors[i] = { claimant: claimant, error: error };
                        return [3 /*break*/, 7];
                    }
                    if (docValid) {
                        throw new Error("did:tls:" + domain + " could not be unambiguously resolved. " + claimants.length + " claimants exist, at least two have a valid claim.");
                    }
                    docValid = true;
                    validAttributes = attributes;
                    _e.label = 7;
                case 7:
                    _b = _a.next();
                    return [3 /*break*/, 2];
                case 8: return [3 /*break*/, 11];
                case 9:
                    e_1_1 = _e.sent();
                    e_1 = { error: e_1_1 };
                    return [3 /*break*/, 11];
                case 10:
                    try {
                        if (_b && !_b.done && (_d = _a.return)) _d.call(_a);
                    }
                    finally { if (e_1) throw e_1.error; }
                    return [7 /*endfinally*/];
                case 11:
                    if (!docValid) {
                        throw new Error("did:tls:" + domain + " could not be validly resolved. " + errors);
                    }
                    return [2 /*return*/, validAttributes];
            }
        });
    });
}
/**
 * Iterates thru events to validate TLS-DID
 *
 * @param {Event[]} events - Set of events
 * @param {string} domain - TLS-DID identifier (domain)
 * @param {pki.CAStore} caStore - node-forge CA certificate store
 *
 * @returns {Attribute[]} - Set off TLS-DID attributes
 */
function processEvents(events, domain, caStore) {
    var e_2, _a;
    var attributes = [];
    var signature;
    var expiry;
    var chain;
    try {
        for (var events_1 = __values(events), events_1_1 = events_1.next(); !events_1_1.done; events_1_1 = events_1.next()) {
            var event = events_1_1.value;
            switch (true) {
                case event.event == 'AttributeChanged':
                    var path = event.args.path;
                    var value = event.args.value;
                    attributes.push({ path: path, value: value });
                    break;
                case event.event == 'ExpiryChanged' && expiry == null:
                    var expiryMS = event.args.expiry.toNumber();
                    expiry = new Date(expiryMS);
                    var now = new Date();
                    if (expiry && expiry < now) {
                        throw new Error('TLS-DID expired');
                    }
                    break;
                case event.event == 'SignatureChanged' && signature == null:
                    signature = event.args.signature;
                    break;
                case event.event == 'ChainChanged' && chain == null:
                    chain = utils_1.chainToCerts(event.args.chain);
                    var chainValid = utils_1.verifyChain(chain, domain, caStore);
                    if (!chainValid) {
                        throw new Error('TLS certificate chain invalid');
                    }
                    break;
            }
        }
    }
    catch (e_2_1) { e_2 = { error: e_2_1 }; }
    finally {
        try {
            if (events_1_1 && !events_1_1.done && (_a = events_1.return)) _a.call(events_1);
        }
        finally { if (e_2) throw e_2.error; }
    }
    if (!chain) {
        //No chain change events found for claimant
        throw new Error('No TLS certificate chain');
    }
    //Hash contract values
    var hash = tls_did_utils_1.hashContract(domain, attributes, expiry, chain);
    //Check for correct signature
    var signatureValid = tls_did_utils_1.verify(chain[0], signature, hash);
    if (!signatureValid) {
        throw new Error('Signature invalid');
    }
    return attributes;
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
//# sourceMappingURL=resolver.js.map