import crypto from 'crypto';
import { readFileSync } from 'fs';
import { ethers } from 'ethers';
import filterAsync from 'node-filter-async';
import SSLCertificate from 'get-ssl-certificate';
import TLSDIDJson from 'tls-did-registry/build/contracts/TLSDID.json';
import TLSDIDRegistryJson from 'tls-did-registry/build/contracts/TLSDIDRegistry.json';

//TODO import from tls-did-registry or tls-did-resolver
const REGISTRY = '0xe28131a74c9Fb412f0e57AD4614dB1A8D6a01793';

interface attribute {
  path: string
  value: string
}

function verify(pemCert: string, signature: string, data: string) {
  const signatureBuffer = Buffer.from(signature, 'base64');
  const verifier = crypto.createVerify('sha256');
  verifier.update(data);
  verifier.end();
  const valid = verifier.verify(pemCert, signatureBuffer);
  return valid;
}

export function hashContract(domain: string, address: string, attributes?: attribute[], expiry?: number) {
  //TODO test use byte array?
  let attributeString = '';
  if (attributes) {
    attributes.forEach(
      (attribute) => (attributeString += attribute.path + attribute.value)
    );
  }

  let expiryString = '';
  if (expiry) {
    expiryString = expiry.toString();
  }

  const stringified = domain + address + attributeString + expiry;
  const hasher = crypto.createHash('sha256');
  hasher.update(stringified);
  const hash = hasher.digest('base64');
  return hash;
}

export class Resolver {
  private provider: ethers.providers.JsonRpcProvider;
  private registry: ethers.Contract;

  constructor(provider, registryAddress) {
    this.provider = provider;
    this.configureRegistry(REGISTRY || registryAddress);
  }

  private configureRegistry(registryAddress: string) {
    const registry = new ethers.Contract(
      registryAddress,
      TLSDIDRegistryJson.abi,
      this.provider
    );
    this.registry = registry;
  }

  private async resolveContract(did: string) {
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

  private async getCertFromServer(did: string) {
    const domain = did.substring(8);
    const certificate = await SSLCertificate.get(domain);
    return certificate.pemEncoded;
  }

  private debugCert() {
    const pemPath = '/__tests__/ssl/certs/testserver.pem';
    const cert = readFileSync(__dirname + pemPath, 'utf8');
    return cert;
  }

  private async checkContractSignature(did, contract) {
    const signature = await contract.signature();

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

    const attributeCount = await contract.getAttributeCount();
    let attributes = [];
    for (let i = 0; i < attributeCount; i++) {
      const attribute = await contract.getAttribute(i);
      const path = attribute['0'];
      const value = attribute['1'];
      attributes.push({ path, value });
    }

    let expiry = await contract.expiry();
    if (!attributes) {
      attributes = [];
    }
    if (expiry.isZero()) {
      expiry = '';
    }
    const hash = hashContract(didDomain, address, attributes, expiry);

    // const pem = await this.getCertFromServer(did);

    //Check for correct signature
    const cert = this.debugCert();
    const valid = verify(cert, signature, hash);

    return valid;
  }

  async resolve(did) {
    const didContract = await this.resolveContract(did);

    const publicKey = {};
  }
}

export function getResolver(provider, registry) {
  const resolver = new Resolver(provider, registry);
  async function resolve(did) {
    return await resolver.resolve(did);
  }
  return { tls: resolve };
}
