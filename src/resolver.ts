import { rootCertificates as nodeRootCertificates } from 'tls';
import { BigNumber, Contract, providers } from 'ethers';
import TLSDIDJson from 'tls-did-registry/build/contracts/TLSDID.json';
import TLSDIDRegistryContract from 'tls-did-registry/build/contracts/TLSDIDRegistry.json';
import { Attribute, ProviderConfig } from './types';
import { hashContract, verify, addValueAtPath, configureProvider, processChains } from './utils';
import { DIDDocument, DIDResolver } from 'did-resolver';

export const REGISTRY = '0xA725A297b0F81c502df772DBE2D0AEb68788679d';

/**
 * Resolves TLS DID
 *
 * @param {string} did - TLS DID
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Promise<Contract>}
 */
async function resolveContract(
  did: string,
  provider: providers.Provider,
  registryAddress: string,
  rootCertificates: readonly string[]
): Promise<Contract> {
  //Setup TLS DID registry
  const registry = new Contract(registryAddress, TLSDIDRegistryContract.abi, provider);

  //Retrive all addresses stored in the registry for the did
  const domain = did.substring(8);
  const addresses: string[] = await registry.getContracts(domain);
  if (addresses.length === 0) {
    throw new Error('No contract was found');
  }

  //Iterate over all contracts and verify if contract is valid
  //If multiple contracts are valid an error is thrown
  let validContract: Contract;
  let validChain: string[];
  for (let address of addresses) {
    if (address == '0x0000000000000000000000000000000000000000') {
      //DID was deleted
      continue;
    }

    //Create contract object from address.
    const contract = new Contract(address, TLSDIDJson.abi, provider);

    //Retrive tls x509 certs
    const chains = await getChains(contract);
    if (chains.length === 0) {
      throw new Error('No tls certificates were found.');
    }
    const validChains = await processChains(chains, domain, rootCertificates);
    if (validChains.length === 0) {
      //No valid chain
      continue;
    }
    //If multiple chains a present the newest is used

    //Verifies contract with server cert
    let valid;
    try {
      valid = await verifyContract(contract, did, validChains);
    } catch (err) {
      console.log(err);
    }

    if (valid && !validContract) {
      validContract = contract;
      validChain = validChains[0];
    } else if (valid) {
      throw new Error(`${addresses.length} contracts were found. Multiple were valid.`);
    }
  }

  //If single valid contract was found it is returned with its corresponding
  //tls certification in jwk format
  //If no valid contract was found an error is thrown
  if (validContract) {
    return validContract;
  } else {
    //TODO Check did-resolver on how to handle errors
    throw new Error(`${addresses.length} contracts were found. None was valid.`);
  }
}

async function getChains(contract): Promise<string[]> {
  //Retrive all chains from TLS DID contract
  const chainCountBN: BigNumber = await contract.getChainCount();
  const chainCount = chainCountBN.toNumber();
  let chains = [];
  for (let i = 0; i < chainCount; i++) {
    const cert = await contract.getChain(i);
    chains.push(cert);
  }

  return chains;
}

/**
 * Verifies if TLS DID Contract signature is correct
 *
 * @param {ethers.Contract} contract - Ethers contract object
 * @param {string} did - TLS DID
 * @param {string[][]} chains - Certificate chains
 */
async function verifyContract(contract: Contract, did: string, chains: string[][]): Promise<boolean> {
  const signature = await contract.signature();
  //Check for equal domain in DID and contract
  const didDomain = did.substring(8);
  const contractDomain = await contract.domain();
  if (didDomain !== contractDomain) {
    throw new Error('DID identifier does not match contract domain');
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
    throw new Error('Contract expired');
  }

  //Hash contract values
  const hash = hashContract(didDomain, contract.address, attributes, expiry, chains);

  //Check for correct signature
  //Uses newest cert
  const valid = verify(chains[0][0], signature, hash);
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
async function resolveTlsDid(
  did: string,
  config: ProviderConfig = {},
  registryAddress: string = REGISTRY,
  rootCertificates: readonly string[] = nodeRootCertificates
): Promise<DIDDocument> {
  const provider = configureProvider(config);
  const contract = await resolveContract(did, provider, registryAddress, rootCertificates);

  //Set context and subject
  let didDocument: DIDDocument = {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
    publicKey: [],
  };

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
export function getResolver(
  config?: ProviderConfig,
  registryAddress?: string,
  rootCertificates?: string[]
): { [index: string]: DIDResolver } {
  async function resolve(did: string): Promise<DIDDocument> {
    return await resolveTlsDid(did, config, registryAddress, rootCertificates);
  }
  return { tls: resolve };
}
