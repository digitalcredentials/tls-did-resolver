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
exports.checkForOCSPUri = exports.checkOCSP = exports.verifyChains = exports.chainToCerts = exports.configureProvider = exports.addValueAtPath = exports.hashContract = exports.verify = void 0;
var node_forge_1 = require("node-forge");
var crypto_1 = __importDefault(require("crypto"));
var ethers_1 = require("ethers");
var object_hash_1 = __importDefault(require("object-hash"));
var ocsp_1 = __importDefault(require("ocsp"));
/**
 * Verifies if signature is correct
 *
 * @param {string} pemCert - public pem certificate
 * @param {string} signature - signature of data signed with private pem certificate
 * @param {string} data - data that has been signed
 */
function verify(pemCert, signature, data) {
    var signatureBuffer = Buffer.from(signature, 'base64');
    var verifier = crypto_1.default.createVerify('sha256');
    verifier.update(data);
    verifier.end();
    var valid = verifier.verify(pemCert, signatureBuffer);
    return valid;
}
exports.verify = verify;
/**
 * Hashes a TLS DID Contract
 *
 * @param {string} domain - TLS DID domain
 * @param {string} address - TLS DID Contract address
 * @param {Attribute[]} attributes - Additional TLS DID Documents attributes
 * @param {Date} expiry - TLS DID Contract expiry
 * @param {string[][]} chains - TLS DID Contract certificate chains
 */
function hashContract(domain, address, attributes, expiry, chains) {
    if (attributes === void 0) { attributes = []; }
    if (expiry === void 0) { expiry = null; }
    if (chains === void 0) { chains = []; }
    return object_hash_1.default({ domain: domain, address: address, attributes: attributes, expiry: expiry, chains: chains });
}
exports.hashContract = hashContract;
/**
 * Adds a value at a path to an object
 *
 * @param object - Object to which the value is added
 * @param {string} path - Path of value. Exp. 'parent/child' or 'parent[]/child'
 * @param {string} value - Value stored in path
 */
function addValueAtPath(object, path, value) {
    var pathArr = path.split('/');
    var currentObj = object;
    pathArr.forEach(function (key, index) {
        if (index === pathArr.length - 1) {
            if (key.endsWith('[]')) {
                key = key.slice(0, -2);
                if (currentObj[key]) {
                    currentObj[key].push(value);
                }
                else {
                    currentObj[key] = [value];
                }
            }
            else {
                currentObj[key] = value;
            }
        }
        else if (key.endsWith('[]')) {
            key = key.slice(0, -2);
            if (currentObj[key]) {
                currentObj[key].push({});
                currentObj = currentObj[key][currentObj[key].length - 1];
            }
            else {
                currentObj[key] = [{}];
                currentObj = currentObj[key][0];
            }
        }
        else {
            currentObj[key] = {};
            currentObj = currentObj[key];
        }
    });
}
exports.addValueAtPath = addValueAtPath;
/**
 * Returns the configured provider
 * @param {ProviderConfig} conf - Configuration for provider
 */
function configureProvider(conf) {
    if (conf === void 0) { conf = {}; }
    if (conf === null || conf === void 0 ? void 0 : conf.provider) {
        return conf.provider;
    }
    else if (conf === null || conf === void 0 ? void 0 : conf.rpcUrl) {
        return new ethers_1.providers.JsonRpcProvider(conf.rpcUrl);
    }
    else if (conf === null || conf === void 0 ? void 0 : conf.web3) {
        return new ethers_1.providers.Web3Provider(conf.web3.currentProvider);
    }
    else {
        return new ethers_1.providers.JsonRpcProvider('http://localhost:8545');
    }
}
exports.configureProvider = configureProvider;
/**
 * Splits string of pem keys to array of pem keys
 * @param {string} chain - String of aggregated pem certs
 * @return {string[]} - Array of pem cert string
 */
function chainToCerts(chain) {
    return chain.split(/\n(?=-----BEGIN CERTIFICATE-----)/g);
}
exports.chainToCerts = chainToCerts;
/**
 * Verifies pem cert chains against node's rootCertificates and domain
 * @param {string[]} chain - Array of of aggregated pem certs strings
 * @param {string} domain - Domain the leaf certificate should have as subject
 * @return { chain: string}[] - Array of valid chains
 */
function verifyChains(chains, domain, rootCertificates) {
    return __awaiter(this, void 0, void 0, function () {
        var filteredChains, unsupportedRootCertIdxs, pkis, definedPkis, caStore, verifiedChains, _i, filteredChains_1, chain;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    filteredChains = Array.from(new Set(chains));
                    //Create caStore from node's rootCertificates
                    //TODO Add support for EC certs
                    console.log('No Support for EC root certs');
                    unsupportedRootCertIdxs = [];
                    pkis = rootCertificates.map(function (cert, idx) {
                        try {
                            return node_forge_1.pki.certificateFromPem(cert);
                        }
                        catch (_a) {
                            unsupportedRootCertIdxs.push(idx);
                        }
                    });
                    console.log('unsupportedRootCertIdxs', unsupportedRootCertIdxs);
                    definedPkis = pkis.filter(function (pki) { return pki !== undefined; });
                    caStore = node_forge_1.pki.createCaStore(definedPkis);
                    verifiedChains = [];
                    _i = 0, filteredChains_1 = filteredChains;
                    _a.label = 1;
                case 1:
                    if (!(_i < filteredChains_1.length)) return [3 /*break*/, 4];
                    chain = filteredChains_1[_i];
                    return [4 /*yield*/, verifyChain(chain, domain, caStore)];
                case 2:
                    if (_a.sent()) {
                        verifiedChains.push(chain);
                    }
                    _a.label = 3;
                case 3:
                    _i++;
                    return [3 /*break*/, 1];
                case 4: return [2 /*return*/, verifiedChains];
            }
        });
    });
}
exports.verifyChains = verifyChains;
/**
 * Verifies pem cert chains against node's rootCertificates and domain
 * @param {string[]} chain - Array of of aggregated pem certs strings
 * @param {string} domain - Domain the leaf certificate should have as subject
 * @param {pki.CAStore} caStore - Nodes root certificates in a node-forge compliant format
 * @return { chain: string; valid: boolean }[] - Array of objects containing chain and validity
 */
function verifyChain(chain, domain, caStore) {
    return __awaiter(this, void 0, void 0, function () {
        var certificateArray, valid, ocspUri, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    certificateArray = chain.map(function (pem) { return node_forge_1.pki.certificateFromPem(pem); });
                    valid = node_forge_1.pki.verifyCertificateChain(caStore, certificateArray) && verifyCertSubject(chain[0], domain);
                    ocspUri = checkForOCSPUri(certificateArray[0]);
                    if (!ocspUri) return [3 /*break*/, 3];
                    _a = valid;
                    if (!_a) return [3 /*break*/, 2];
                    return [4 /*yield*/, checkOCSP(chain[0], chain[1])];
                case 1:
                    _a = (_b.sent());
                    _b.label = 2;
                case 2:
                    valid = _a;
                    _b.label = 3;
                case 3: return [2 /*return*/, { valid: valid }];
            }
        });
    });
}
/**
 * Verifies that the subject of a x509 certificate
 * @param {string} cert - Website cert in pem format
 * @param {string} subject
 */
function verifyCertSubject(cert, subject) {
    var _a, _b;
    var pkiObject = node_forge_1.pki.certificateFromPem(cert);
    //TODO unclear if multiple subjects can be present in x509 leaf certificate
    //https://www.tools.ietf.org/html/rfc5280#section-4.1.2.6
    return ((_b = (_a = pkiObject.subject) === null || _a === void 0 ? void 0 : _a.attributes[0]) === null || _b === void 0 ? void 0 : _b.value) === subject;
}
/**
 * Checks OCSP
 * @param {string} cert - Website cert in pem format
 * @param {string} issuerCert - Cert of issuer in pem format
 *
 * @returns {Promise<boolean>} - True if valid
 */
function checkOCSP(cert, issuerCert) {
    return __awaiter(this, void 0, void 0, function () {
        var response;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, new Promise(function (resolve, reject) {
                        ocsp_1.default.check({
                            cert: cert,
                            issuer: issuerCert,
                        }, function (err, res) {
                            if (!res)
                                reject(err);
                            else {
                                var valid = res.type === 'good';
                                resolve(valid);
                            }
                        });
                    })];
                case 1:
                    response = _a.sent();
                    return [2 /*return*/, response];
            }
        });
    });
}
exports.checkOCSP = checkOCSP;
/**
 * Checks for OCSP
 * @param {string} cert - Website cert in pem format
 *
 * @returns {Promise<boolean>} - True if available
 */
function checkForOCSPUri(cert) {
    // Return value type incorrect
    var aIAExtension = cert.getExtension('authorityInfoAccess');
    if (aIAExtension === null) {
        return null;
    }
    var aIAValue = node_forge_1.asn1.fromDer(aIAExtension.value);
    var aIAValues = [];
    for (var _i = 0, _a = aIAValue.value; _i < _a.length; _i++) {
        var value = _a[_i];
        var test_1 = node_forge_1.pki;
        aIAValues.push(test_1.certificateExtensionFromAsn1(value));
    }
    var oscpExtensions = aIAValues.filter(function (value) { return (value.id = '1.3.6.1.5.5.7.48.1'); });
    if (oscpExtensions.length === 0) {
        return null;
    }
    return oscpExtensions[0].value;
}
exports.checkForOCSPUri = checkForOCSPUri;
//# sourceMappingURL=utils.js.map