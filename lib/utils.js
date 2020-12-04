"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.processChains = exports.chainToCerts = exports.configureProvider = exports.addValueAtPath = exports.x509ToJwk = exports.hashContract = exports.verify = exports.verifyCertificateChain = void 0;
var tls_1 = require("tls");
var node_forge_1 = require("node-forge");
var crypto_1 = __importDefault(require("crypto"));
var jose_1 = require("jose");
var ethers_1 = require("ethers");
var object_hash_1 = __importDefault(require("object-hash"));
function verifyCertificateChain() {
    console.log(tls_1.rootCertificates);
}
exports.verifyCertificateChain = verifyCertificateChain;
/**
 * Verfies if signature is correct
 *
 * @param {string} pemCert - public pem certificate
 * @param {string} signature - signature of data signiged with private pem certificate
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
 */
function hashContract(domain, address, attributes, expiry) {
    return object_hash_1.default({ domain: domain, address: address, attributes: attributes, expiry: expiry });
}
exports.hashContract = hashContract;
/**
 * Transforms x509 pem certificate to JWKRSAKey
 *
 * @param {string} cert
 */
function x509ToJwk(cert) {
    return jose_1.JWK.asKey(cert).toJWK();
}
exports.x509ToJwk = x509ToJwk;
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
    if (conf.provider) {
        return conf.provider;
    }
    else if (conf.rpcUrl) {
        return new ethers_1.providers.JsonRpcProvider(conf.rpcUrl);
    }
    else if (conf.web3) {
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
 * @param {string} domain - Domain the leaf certificat should have as subject
 * @return { chain: string; valid: boolean }[] - Array of objects containing chain and validity
 */
function processChains(chains, domain) {
    //Filter duplicate chains
    var filterdChains = Array.from(new Set(chains));
    //Create caStore from node's rootCertificates
    //TODO Add support for EC certs
    console.log('No Support for EC root certs');
    var unsupportedRootCertIdxs = [];
    var pkis = tls_1.rootCertificates.map(function (cert, idx) {
        try {
            return node_forge_1.pki.certificateFromPem(cert);
        }
        catch (_a) {
            unsupportedRootCertIdxs.push(idx);
        }
    });
    console.log('unsupportedRootCertIdxs', unsupportedRootCertIdxs);
    var definedPkis = pkis.filter(function (pki) { return pki !== undefined; });
    var caStore = node_forge_1.pki.createCaStore(definedPkis);
    //Verify each chain against the caStore and domain
    var verifiedChains = filterdChains.map(function (chain) {
        var pemArray = chainToCerts(chain);
        return verifyChain(pemArray, domain, caStore);
    });
    return verifiedChains;
}
exports.processChains = processChains;
/**
 * Verifies pem cert chains against node's rootCertificates and domain
 * @param {string[]} chain - Array of of aggregated pem certs strings
 * @param {string} domain - Domain the leaf certificat should have as subject
 * @param {pki.CAStore} caStore - Nodes root certificates in a node-forge compliant format
 * @return { chain: string; valid: boolean }[] - Array of objects containing chain and validity
 */
function verifyChain(chain, domain, caStore) {
    var certificateArray = chain.map(function (pem) { return node_forge_1.pki.certificateFromPem(pem); });
    var valid = node_forge_1.pki.verifyCertificateChain(caStore, certificateArray) && verifyCertSubject(chain[0], domain);
    return { chain: chain, valid: valid };
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
//# sourceMappingURL=utils.js.map