"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.addValueAtPath = exports.x509ToJwk = exports.hashContract = exports.verify = void 0;
var crypto_1 = __importDefault(require("crypto"));
var jose_1 = require("jose");
function verify(pemCert, signature, data) {
    var signatureBuffer = Buffer.from(signature, 'base64');
    var verifier = crypto_1.default.createVerify('sha256');
    verifier.update(data);
    verifier.end();
    var valid = verifier.verify(pemCert, signatureBuffer);
    return valid;
}
exports.verify = verify;
//TODO Explore byte array
function hashContract(domain, address, attributes, expiry) {
    var attributeString = '';
    if (attributes) {
        attributes.forEach(function (attribute) { return (attributeString += attribute.path + attribute.value); });
    }
    var expiryString = '';
    if (expiry) {
        expiryString = expiry.toString();
    }
    var stringified = domain + address + attributeString + expiryString;
    var hasher = crypto_1.default.createHash('sha256');
    hasher.update(stringified);
    var hash = hasher.digest('base64');
    return hash;
}
exports.hashContract = hashContract;
function x509ToJwk(cert) {
    var jwk = jose_1.JWK.asKey(cert);
    return jwk;
}
exports.x509ToJwk = x509ToJwk;
function addValueAtPath(object, path, value) {
    var pathArr = path.split('/');
    var currentObj = object;
    pathArr.forEach(function (key, index) {
        if (index === pathArr.length - 1) {
            currentObj[key] = value;
        }
        else {
            currentObj[key] = {};
            currentObj = currentObj[key];
        }
    });
}
exports.addValueAtPath = addValueAtPath;
//# sourceMappingURL=utils.js.map