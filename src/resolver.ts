import { readFileSync } from 'fs';
import { ethers } from 'ethers';
import filterAsync from 'node-filter-async';
import SSLCertificate from 'get-ssl-certificate';
import TLSDIDJson from 'tls-did-registry/build/contracts/TLSDID.json';
import TLSDIDRegistryJson from 'tls-did-registry/build/contracts/TLSDIDRegistry.json';
import { hashContract, verify, x509ToJwk, addValueAtPath } from './utils'
import { JWK } from 'jose';

export const REGISTRY = '0xefd425B44ed72fD3F7829007214Ba4907BFAF4D5';

class Resolver {
  private provider: ethers.providers.JsonRpcProvider;
  private registry: ethers.Contract;
  public x509Certificate: string;

  constructor(provider: ethers.providers.JsonRpcProvider, registryAddress: string) {
    this.provider = provider;
    this.configureRegistry(REGISTRY || registryAddress);
  }

  private configureRegistry(registryAddress: string): void {
    const registry = new ethers.Contract(
      registryAddress,
      TLSDIDRegistryJson.abi,
      this.provider
    );
    this.registry = registry;
  }

  private async resolveContract(did: string): Promise<{contract: ethers.Contract, jwk: JWK.RSAKey}> {
    const addresses = await this.registry.getContracts(did);

    let validContract: ethers.Contract;
    let cert: string;

    for(let address of addresses) {
      const contract = new ethers.Contract(
        address,
        TLSDIDJson.abi,
        this.provider
      );

      const verificationCert = this.debugCert();
      const valid = await this.verifyContract(contract, did, verificationCert);

      if(valid && !validContract) {
        validContract = contract;
        cert = verificationCert;
      } else if (valid) {
        //TODO Check did-resolver on how to handle errors
        throw new Error('Multiple valid contracts where found');
      }
    }

    if(validContract) {
      const jwk = x509ToJwk(cert);
      return {contract: validContract, jwk};
    } else {
      //TODO Check did-resolver on how to handle errors
      throw new Error('No valid contract was found');
    }
  }

  private async getCertFromServer(did: string): Promise<string> {
    const domain = did.substring(8);
    const cert = await SSLCertificate.get(domain);
    return cert.pemEncoded;
  }

  private debugCert(): string {
    const pemPath = '/__tests__/ssl/certs/testserver.pem';
    const cert = readFileSync(__dirname + pemPath, 'utf8');
    return cert;
  }

  private async verifyContract(contract: ethers.Contract, did: string, cert: string): Promise<boolean> {
    console.log("Debug1a");
    const signature = await contract.signature();
    console.log("Debug2a");

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

    //Check for correct signature
    const valid = verify(cert, signature, hash);

    return valid;
  }

  async resolve(did: string): Promise<object> {
    const {contract, jwk} = await this.resolveContract(did);

    const didDocument = {
      "@context": "https://www.w3.org/ns/did/v1",
      "id": did,
    }

    didDocument["verificationMethod"] = [{
      "id": `${did}#keys-1`,
      "type": "JsonWebKey2020",
      "controller": did,
      "publicKeyJwk": jwk
    }];



    const attributeCount = await contract.getAttributeCount();
    for (let i = 0; i < attributeCount; i++) {
      const attribute = await contract.getAttribute(i);
      const path = attribute['0'];
      const value = attribute['1'];
      addValueAtPath(didDocument, path, value);
    }
    return didDocument;
  }
}

export function getResolver(provider, registry: string): { tls:(did: any) => Promise<object> } {
  const resolver = new Resolver(provider, registry);
  async function resolve(did) {
    return await resolver.resolve(did);
  }
  return { tls: resolve };
}
