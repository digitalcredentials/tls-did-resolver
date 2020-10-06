"use strict";

var _ethjsProviderHttp = _interopRequireDefault(require("ethjs-provider-http"));

var _ethjsQuery = _interopRequireDefault(require("ethjs-query"));

var _ethjsAbi = _interopRequireDefault(require("ethjs-abi"));

var _bn = _interopRequireDefault(require("bn.js"));

var _ethjsContract = _interopRequireDefault(require("ethjs-contract"));

var _tlsDidContract = _interopRequireDefault(require("../contracts/tls-did-contract.json"));

var _buffer = require("buffer");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function configureProvider(conf) {
  return new _ethjsProviderHttp.default(conf.rpcUrl);
}

function configureNetwork(conf = {}) {
  const provider = configureProvider(conf);
  const eth = new _ethjsQuery.default(provider);
  const DidReg = new _ethjsContract.default(eth)(_tlsDidContract.default);
  const didReg = DidReg.at(conf.registry);
  return didReg;
}

const didReg = configureNetwork({
  rpcUrl: 'http://127.0.0.1:8545',
  registry: '0x82c5046fA510692d9D297B1b3256420FD2c8F084'
});

http: didReg.signature.call().then(signature => {
  console.log(signature);
});