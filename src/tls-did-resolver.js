import crypto from 'crypto';
import { readFileSync } from 'fs';
import { ethers } from 'ethers';
import filterAsync from 'node-filter-async';
import SSLCertificate from 'get-ssl-certificate';
import TLSDIDJson from 'tls-did-registry/build/contracts/TLSDID.json';
import TLSDIDRegistryJson from 'tls-did-registry/build/contracts/TLSDIDRegistry.json';

//TODO import from tls-did-registry or tls-did-resolver
const REGISTRY = '0xF7fBa67a3f6b05A9E0DA8DcB1f44aE037134eAE4';

function verify(pemCert, signature, data) {
  const signatureBuffer = new Buffer.from(signature, 'base64');
  const verifier = crypto.createVerify('sha256');
  verifier.update(data);
  verifier.end();
  const valid = verifier.verify(pemCert, signatureBuffer);
  return valid;
}
class Resolver {
  constructor(provider, registryAddress) {
    this.provider = provider;
    this.configureRegistry(REGISTRY || registryAddress);
  }

  configureRegistry(registryAddress) {
    const registry = new ethers.Contract(
      REGISTRY,
      TLSDIDRegistryJson.abi,
      this.provider
    );
    this.registry = registry;
  }

  async resolveDIDSC(did) {
    const addresses = await this.registry.getContracts(did);

    const contracts = addresses.map((address) => {
      const contract = new ethers.Contract(
        address,
        TLSDIDJson.abi,
        this.provider
      );
      return contract;
    });

    const validContracts = await filterAsync(
      contracts,
      async (contract) => await this.checkContractSignature(did, contract)
    );

    if (validContracts.length == 1) {
      return validContracts[0];
    } else if (validContracts.length > 1) {
      throw new Error('Multiple valid contracts where found');
    } else {
      throw new Error('No valid contract was found');
    }
  }

  async getCertFromServer(did) {
    const domain = did.substring(8);
    const certificate = await SSLCertificate.get(domain);
    return certificate.pemEncoded;
  }

  debugCert() {
    const pemPath = '/__tests__/ssl/certs/testserver.pem';
    const cert = readFileSync(__dirname + pemPath, 'utf8');
    return cert;
  }

  async checkContractSignature(did, contract) {
    const signature = await contract.signature();

    console.log('signature', signature);

    //Check for equal domain in DID and Contract
    //TODO implement if values are empty/undefined => ""
    //TODO test use buffer?
    const didDomain = did.substring(8);
    const contractDomain = await contract.domain();
    if (didDomain !== contractDomain) {
      return false;
    }

    //Create hash of contract values
    //TODO check to string methods
    const address = await contract.address;
    let attributes = await contract.getAttributes();
    let expiry = await contract.expiry();
    if (!attributes) {
      attributes = '';
    }
    if (expiry.isZero()) {
      expiry = '';
    }
    const stringified = didDomain + address + attributes + expiry;

    const hasher = crypto.createHash('sha256');
    hasher.update(stringified);
    const hash = hasher.digest('base64');

    // const pem = await this.getCertFromServer(did);

    //Check for correct signature
    const cert = this.debugCert();
    const valid = verify(cert, signature, hash);

    console.log('valid', valid);

    return valid;
  }

  resolveDID(did) {
    const didContract = this.resolveDIDSC(did);

    const publicKey = {};
  }
}

export default Resolver;
