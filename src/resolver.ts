import { Contract, providers } from 'ethers';
import { JWK } from 'jose';
import TLSDIDJson from 'tls-did-registry/build/contracts/TLSDID.json';
import TLSDIDRegistryJson from 'tls-did-registry/build/contracts/TLSDIDRegistry.json';
import { hashContract, verify, x509ToJwk, addValueAtPath, getCertFromServer, debugCert } from './utils';

export const REGISTRY = '0xefd425B44ed72fD3F7829007214Ba4907BFAF4D5';

async function resolveContract(
  provider: providers.JsonRpcProvider,
  registryAddress: string,
  did: string
): Promise<{ contract: Contract; jwk: JWK.RSAKey }> {
  const registry = new Contract(registryAddress, TLSDIDRegistryJson.abi, provider);
  const addresses = await registry.getContracts(did);

  let validContract: Contract;
  let cert = debugCert();

  for (let address of addresses) {
    const contract = new Contract(address, TLSDIDJson.abi, provider);

    const valid = await verifyContract(contract, did, cert);

    if (valid && !validContract) {
      validContract = contract;
    } else if (valid) {
      //TODO Check did-resolver on how to handle errors
      throw new Error('Multiple valid contracts where found');
    }
  }

  if (validContract) {
    const jwk = x509ToJwk(cert);
    return { contract: validContract, jwk };
  } else {
    //TODO Check did-resolver on how to handle errors
    throw new Error('No valid contract was found');
  }
}

async function verifyContract(contract: Contract, did: string, cert: string): Promise<boolean> {
  const signature = await contract.signature();

  //Check for equal domain in DID and Contract
  const didDomain = did.substring(8);
  const contractDomain = await contract.domain();
  if (didDomain !== contractDomain) {
    return false;
  }

  //Create hash of contract values
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

async function resolveTlsDid(provider: providers.JsonRpcProvider, registryAddress: string, did: string): Promise<object> {
  const { contract, jwk } = await resolveContract(provider, registryAddress, did);

  const didDocument = {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
  };

  didDocument['verificationMethod'] = [
    {
      id: `${did}#keys-1`,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: jwk,
    },
  ];

  const attributeCount = await contract.getAttributeCount();
  for (let i = 0; i < attributeCount; i++) {
    const attribute = await contract.getAttribute(i);
    const path = attribute['0'];
    const value = attribute['1'];
    addValueAtPath(didDocument, path, value);
  }
  return didDocument;
}

export function getResolver(provider, registry: string): { tls: (did: any) => Promise<object> } {
  async function resolve(did) {
    return await resolveTlsDid(provider, registry, did);
  }
  return { tls: resolve };
}
