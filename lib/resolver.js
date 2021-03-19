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
var tls_did_utils_1 = require("@digitalcredentials/tls-did-utils");
var utils_1 = require("./utils");
var did_resolver_1 = require("did-resolver");
var chain_1 = require("./chain");
/**
 * Gets TLS DID Resolver
 *
 * @param {ProviderConfig} config - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
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
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
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
                    provider = tls_did_utils_1.configureProvider(config);
                    return [4 /*yield*/, chain_1.newRegistry(provider, registryAddress)];
                case 1:
                    registry = _a.sent();
                    return [4 /*yield*/, chain_1.getClaimants(registry, domain)];
                case 2:
                    claimants = _a.sent();
                    return [4 /*yield*/, resolveClaims(rootCertificates, registry, domain, claimants)];
                case 3:
                    attributes = _a.sent();
                    return [2 /*return*/, buildDIDDocument(did, attributes)];
            }
        });
    });
}
function resolveClaims(rootCertificates, registry, domain, claimants) {
    return __awaiter(this, void 0, void 0, function () {
        var caStore, validAttributes, docValid, _i, claimants_1, claimant, events, _a, docObject, valid, hash;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    caStore = utils_1.createCaStore(rootCertificates);
                    validAttributes = [];
                    docValid = false;
                    _i = 0, claimants_1 = claimants;
                    _b.label = 1;
                case 1:
                    if (!(_i < claimants_1.length)) return [3 /*break*/, 4];
                    claimant = claimants_1[_i];
                    return [4 /*yield*/, chain_1.resolveClaimant(registry, domain, claimant)];
                case 2:
                    events = _b.sent();
                    if (events.length === 0) {
                        //No change events found for claimant
                        return [3 /*break*/, 3];
                    }
                    _a = processEvents(events, domain, caStore), docObject = _a.docObject, valid = _a.valid;
                    if (!docObject.chain) {
                        //No chain change events found for claimant
                        return [3 /*break*/, 3];
                    }
                    if (valid) {
                        hash = tls_did_utils_1.hashContract(domain, docObject.attributes, docObject.expiry, docObject.chain);
                        //Check for correct signature
                        valid = tls_did_utils_1.verify(docObject.chain[0], docObject.signature, hash);
                        if (!valid) {
                            //Signatures does not match data
                            return [3 /*break*/, 3];
                        }
                    }
                    if (valid && docValid) {
                        throw new Error("did:tls:" + domain + " could not be unambiguously resolved");
                    }
                    if (valid) {
                        docValid = true;
                        validAttributes = docObject.attributes;
                    }
                    _b.label = 3;
                case 3:
                    _i++;
                    return [3 /*break*/, 1];
                case 4:
                    if (!docValid) {
                        throw new Error("did:tls:" + domain + " could not be validly resolved");
                    }
                    return [2 /*return*/, validAttributes];
            }
        });
    });
}
function processEvents(events, domain, caStore) {
    var attributes = [];
    var signature;
    var expiry;
    var chain;
    var invalid = false;
    for (var _i = 0, events_1 = events; _i < events_1.length; _i++) {
        var event = events_1[_i];
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
                    invalid = true;
                    continue;
                }
                break;
            case event.event == 'SignatureChanged' && signature == null:
                signature = event.args.signature;
                break;
            case event.event == 'ChainChanged' && chain == null:
                chain = utils_1.chainToCerts(event.args.chain);
                var chainValid = utils_1.verifyChain(chain, domain, caStore);
                if (!chainValid) {
                    invalid = true;
                    continue;
                }
                break;
        }
    }
    return { docObject: { attributes: attributes, signature: signature, expiry: expiry, chain: chain }, valid: !invalid };
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