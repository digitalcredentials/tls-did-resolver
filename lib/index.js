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
exports.getResolver = exports.Resolver = exports.hashContract = void 0;
var crypto_1 = __importDefault(require("crypto"));
var fs_1 = require("fs");
var ethers_1 = require("ethers");
var node_filter_async_1 = __importDefault(require("node-filter-async"));
var get_ssl_certificate_1 = __importDefault(require("get-ssl-certificate"));
var TLSDID_json_1 = __importDefault(require("tls-did-registry/build/contracts/TLSDID.json"));
var TLSDIDRegistry_json_1 = __importDefault(require("tls-did-registry/build/contracts/TLSDIDRegistry.json"));
//TODO import from tls-did-registry or tls-did-resolver
var REGISTRY = '0xe28131a74c9Fb412f0e57AD4614dB1A8D6a01793';
function verify(pemCert, signature, data) {
    var signatureBuffer = Buffer.from(signature, 'base64');
    var verifier = crypto_1.default.createVerify('sha256');
    verifier.update(data);
    verifier.end();
    var valid = verifier.verify(pemCert, signatureBuffer);
    return valid;
}
function hashContract(domain, address, attributes, expiry) {
    //TODO test use byte array?
    var attributeString = '';
    if (attributes) {
        attributes.forEach(function (attribute) { return (attributeString += attribute.path + attribute.value); });
    }
    var expiryString = '';
    if (expiry) {
        expiryString = expiry.toString();
    }
    var stringified = domain + address + attributeString + expiry;
    var hasher = crypto_1.default.createHash('sha256');
    hasher.update(stringified);
    var hash = hasher.digest('base64');
    return hash;
}
exports.hashContract = hashContract;
var Resolver = /** @class */ (function () {
    function Resolver(provider, registryAddress) {
        this.provider = provider;
        this.configureRegistry(REGISTRY || registryAddress);
    }
    Resolver.prototype.configureRegistry = function (registryAddress) {
        var registry = new ethers_1.ethers.Contract(registryAddress, TLSDIDRegistry_json_1.default.abi, this.provider);
        this.registry = registry;
    };
    Resolver.prototype.resolveContract = function (did) {
        return __awaiter(this, void 0, void 0, function () {
            var addresses, contracts, validContracts;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.registry.getContracts(did)];
                    case 1:
                        addresses = _a.sent();
                        contracts = addresses.map(function (address) {
                            var contract = new ethers_1.ethers.Contract(address, TLSDID_json_1.default.abi, _this.provider);
                            return contract;
                        });
                        return [4 /*yield*/, node_filter_async_1.default(contracts, function (contract) { return __awaiter(_this, void 0, void 0, function () { return __generator(this, function (_a) {
                                switch (_a.label) {
                                    case 0: return [4 /*yield*/, this.checkContractSignature(did, contract)];
                                    case 1: return [2 /*return*/, _a.sent()];
                                }
                            }); }); })];
                    case 2:
                        validContracts = _a.sent();
                        if (validContracts.length == 1) {
                            return [2 /*return*/, validContracts[0]];
                        }
                        else if (validContracts.length > 1) {
                            throw new Error('Multiple valid contracts where found');
                        }
                        else {
                            throw new Error('No valid contract was found');
                        }
                        return [2 /*return*/];
                }
            });
        });
    };
    Resolver.prototype.getCertFromServer = function (did) {
        return __awaiter(this, void 0, void 0, function () {
            var domain, certificate;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        domain = did.substring(8);
                        return [4 /*yield*/, get_ssl_certificate_1.default.get(domain)];
                    case 1:
                        certificate = _a.sent();
                        return [2 /*return*/, certificate.pemEncoded];
                }
            });
        });
    };
    Resolver.prototype.debugCert = function () {
        var pemPath = '/__tests__/ssl/certs/testserver.pem';
        var cert = fs_1.readFileSync(__dirname + pemPath, 'utf8');
        return cert;
    };
    Resolver.prototype.checkContractSignature = function (did, contract) {
        return __awaiter(this, void 0, void 0, function () {
            var signature, didDomain, contractDomain, address, attributeCount, attributes, i, attribute, path, value, expiry, hash, cert, valid;
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
                        return [4 /*yield*/, contract.address];
                    case 3:
                        address = _a.sent();
                        return [4 /*yield*/, contract.getAttributeCount()];
                    case 4:
                        attributeCount = _a.sent();
                        attributes = [];
                        i = 0;
                        _a.label = 5;
                    case 5:
                        if (!(i < attributeCount)) return [3 /*break*/, 8];
                        return [4 /*yield*/, contract.getAttribute(i)];
                    case 6:
                        attribute = _a.sent();
                        path = attribute['0'];
                        value = attribute['1'];
                        attributes.push({ path: path, value: value });
                        _a.label = 7;
                    case 7:
                        i++;
                        return [3 /*break*/, 5];
                    case 8: return [4 /*yield*/, contract.expiry()];
                    case 9:
                        expiry = _a.sent();
                        if (!attributes) {
                            attributes = [];
                        }
                        if (expiry.isZero()) {
                            expiry = '';
                        }
                        hash = hashContract(didDomain, address, attributes, expiry);
                        cert = this.debugCert();
                        valid = verify(cert, signature, hash);
                        return [2 /*return*/, valid];
                }
            });
        });
    };
    Resolver.prototype.resolve = function (did) {
        return __awaiter(this, void 0, void 0, function () {
            var didContract, publicKey;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.resolveContract(did)];
                    case 1:
                        didContract = _a.sent();
                        publicKey = {};
                        return [2 /*return*/];
                }
            });
        });
    };
    return Resolver;
}());
exports.Resolver = Resolver;
function getResolver(provider, registry) {
    var resolver = new Resolver(provider, registry);
    function resolve(did) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, resolver.resolve(did)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    }
    return { tls: resolve };
}
exports.getResolver = getResolver;
//# sourceMappingURL=index.js.map