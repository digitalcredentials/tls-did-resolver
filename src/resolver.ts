import { BigNumber, Contract, providers } from 'ethers';
import { JWKRSAKey } from 'jose';
import TLSDIDJson from 'tls-did-registry/build/contracts/TLSDID.json';
import TLSDIDRegistryJson from 'tls-did-registry/build/contracts/TLSDIDRegistry.json';
import { Attribute, ProviderConfig, Resolver } from './types';
import { hashContract, verify, x509ToJwk, addValueAtPath, getCertFromServer, debugCert, configureProvider } from './utils';

export const REGISTRY = '0x33fD81799f172C8C932C9a3Fbc7dda9cdE26880A';

/**
 * Resolves TLS DID
 *
 * @param {string} did - TLS DID
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Promise<{ contract: Contract; jwk: JWKRSAKey }>}
 */
async function resolveContract(
  did: string,
  provider: providers.Provider,
  registryAddress: string
): Promise<{ contract: Contract; jwk: JWKRSAKey }> {
  //Setup TLS DID registry
  const registry = new Contract(registryAddress, TLSDIDRegistryJson.abi, provider);

  //Retrive all addresses stored in the registry for the did
  const domain = did.substring(8);
  const addresses = await registry.getContracts(domain);
  if (addresses.length === 0) {
    throw new Error('No contract was found');
  }

  //Retrive tls certification
  //TODO retrive from contract
  //let cert = (await getCertFromServer(domain)).pemEncoded;
  let cert = debugCert();

  //Iterate over all contracts and verify if contract is valid
  //If multiple contracts are valid an error is thrown
  let validContract: Contract;
  for (let address of addresses) {
    const contract = new Contract(address, TLSDIDJson.abi, provider);

    const valid = await verifyContract(contract, did, cert);

    if (valid && !validContract) {
      validContract = contract;
    } else if (valid) {
      throw new Error(`${addresses.length} contracts were found. Multiple were valid.`);
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
    throw new Error(`${addresses.length} contracts were found. None was valid.`);
  }
}

/**
 * Verifies if TLS DID Contract signature is correct
 *
 * @param {ethers.Contract} contract - Ethers contract object
 * @param {string} did - TLS DID
 * @param {string} cert - Public pem certificate
 */
async function verifyContract(contract: Contract, did: string, cert: string): Promise<boolean> {
  const signature = await contract.signature();
  //Check for equal domain in DID and contract
  const didDomain = did.substring(8);
  const contractDomain = await contract.domain();
  if (didDomain !== contractDomain) {
    return false;
  }

  //Retrive all attributes from the contract
  let attributes: Attribute[] = [];
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
  const now = new Date();
  if (expiry && expiry < now) {
    return false;
  }

  //Hash contract values
  const hash = hashContract(didDomain, contract.address, attributes, expiry);

  //Check for correct signature
  const valid = verify(cert, signature, hash);
  return valid;
}

/**
 * Resolves TLS DID
 *
 * @param {string} did - TLS DID
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Promise<DIDDocumentObject>}
 */
async function resolveTlsDid(did: string, config: ProviderConfig = {}, registryAddress: string = REGISTRY): Promise<object> {
  const provider = configureProvider(config);
  const { contract, jwk } = await resolveContract(did, provider, registryAddress);

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

/**
 * Gets TLS DID Resolver
 *
 * @param {ProviderConfig} config - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Resolver}
 */
export function getResolver(config?: ProviderConfig, registryAddress?: string): Resolver {
  async function resolve(did) {
    return await resolveTlsDid(did, config, registryAddress);
  }
  return { tls: resolve };
}
