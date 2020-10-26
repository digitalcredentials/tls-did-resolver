import { BigNumber, Contract, providers } from 'ethers';
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
  //Setup TLS DID registry
  const registry = new Contract(registryAddress, TLSDIDRegistryJson.abi, provider);

  //Retrive all addresses stored in the registry for the did
  const addresses = await registry.getContracts(did);

  //Retrive tls certification
  let cert = await getCertFromServer(did);

  //Iterate over all contracts and verify if contract is valid
  //If multiple contracts are valid an error is thrown
  let validContract: Contract;
  for (let address of addresses) {
    const contract = new Contract(address, TLSDIDJson.abi, provider);

    const valid = await verifyContract(contract, did, cert);

    if (valid && !validContract) {
      validContract = contract;
    } else if (valid) {
      throw new Error('Multiple valid contracts where found');
    }
  }

  //If single valid contract was found it is returned with its corresponding
  //tls certification in jwk format
  //If no valid contract was found an error is thrown
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

  //Check for equal domain in DID and contract
  const didDomain = did.substring(8);
  const contractDomain = await contract.domain();
  if (didDomain !== contractDomain) {
    return false;
  }

  //Retrive all attributes from the contract
  let attributes: IAttribute[] = [];
  let attributeCountBN: BigNumber;
  attributeCountBN = await contract.getAttributeCount();
  const attributeCount = attributeCountBN.toNumber();
  for (let i = 0; i < attributeCount; i++) {
    const attribute = await contract.getAttribute(i);
    const path = attribute['0'];
    const value = attribute['1'];
    attributes.push({ path, value });
  }

  //Retrive expiry from contract and check if expired
  let expiryBN: BigNumber;
  expiryBN = await contract.expiry();
  const expiry = new Date(expiryBN.toNumber());
  const today = new Date();
  if (expiry && expiry < today) {
    return false;
  }

  //Hash contract values
  const hash = hashContract(didDomain, contract.address, attributes, expiry);

  //Check for correct signature
  const valid = verify(cert, signature, hash);

  return valid;
}

async function resolveTlsDid(provider: providers.JsonRpcProvider, registryAddress: string, did: string): Promise<object> {
  const { contract, jwk } = await resolveContract(provider, registryAddress, did);

  //Set context and subject
  const didDocument = {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
  };

  //Set verification method based on JWK representation of tls pem certificate
  didDocument['verificationMethod'] = [
    {
      id: `${did}#keys-1`,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: jwk,
    },
  ];

  //Set attributes by appending attribute values to the DID Document object
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
