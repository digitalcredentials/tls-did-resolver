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
exports.addValueAtPath = exports.x509ToJwk = exports.debugCert = exports.getCertFromServer = exports.hashContract = exports.verify = void 0;
var crypto_1 = __importDefault(require("crypto"));
var jose_1 = require("jose");
var fs_1 = require("fs");
var get_ssl_certificate_1 = __importDefault(require("get-ssl-certificate"));
var object_hash_1 = __importDefault(require("object-hash"));
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
    return object_hash_1.default({ domain: domain, address: address, attributes: attributes, expiry: expiry });
}
exports.hashContract = hashContract;
function getCertFromServer(did) {
    return __awaiter(this, void 0, void 0, function () {
        var domain;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    domain = did.substring(8);
                    return [4 /*yield*/, get_ssl_certificate_1.default.get(domain)];
                case 1: return [2 /*return*/, _a.sent()];
            }
        });
    });
}
exports.getCertFromServer = getCertFromServer;
function debugCert() {
    var pemPath = '/__tests__/ssl/certs/testserver.pem';
    return fs_1.readFileSync(__dirname + pemPath, 'utf8');
}
exports.debugCert = debugCert;
function x509ToJwk(cert) {
    return jose_1.JWK.asKey(cert);
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