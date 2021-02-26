import { rootCertificates as nodeRootCertificates } from 'tls';
import { Contract } from 'ethers';
import { Attribute, ProviderConfig } from './types';
import { hashContract, verify, addValueAtPath, configureProvider, verifyChains } from './utils';
import { DIDDocument, DIDResolver, ParsedDID, parse } from 'did-resolver';
import { getContracts, getAttributes, getChains, getDomain, getExpiry, getSignature, REGISTRY } from './chain';

/**
 * Resolves TLS DID
 *
 * @param {string} did - TLS DID
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Promise<Contract>}
 */
async function processContracts(
  domain: string,
  contracts: Contract[],
  rootCertificates: readonly string[]
): Promise<Attribute[]> {
  //Iterate over all contracts and verify if contract is valid
  //If multiple contracts are valid an error is thrown
  let validContract: Contract;
  let validChain: string[];
  let validAttributes: Attribute[];
  for (let contract of contracts) {
    //Retrieve tls x509 certs
    const chains = await getChains(contract);
    if (chains.length === 0) {
      //No chain
      continue;
    }
    const validChains = await verifyChains(chains, domain, rootCertificates);
    if (validChains.length === 0) {
      //No valid chain
      continue;
    }
    //If multiple chains are present the newest is used

    //Check for equal domain in DID and contract
    const contractDomain = await getDomain(contract);
    if (domain !== contractDomain) {
      //DID domain and contract domain to not match
      continue;
    }

    //Retrieve expiry from contract and check if expired
    const expiry = await getExpiry(contract);
    const now = new Date();
    if (expiry && expiry < now) {
      //Contract expired
      continue;
    }

    //Retrieve all attributes from the contract
    const attributes = await getAttributes(contract);

    //Retrieve signature from the contract
    const signature = await getSignature(contract);

    //Hash contract values
    const hash = hashContract(domain, contract.address, attributes, expiry, chains);

    //Check for correct signature
    //Uses newest cert
    const valid = verify(chains[0][0], signature, hash);
    if (!valid) {
      //Signatures does not match data
      continue;
    }

    if (valid && !validContract) {
      validContract = contract;
      validChain = validChains[0];
      validAttributes = attributes;
    } else if (valid) {
      throw new Error(`${contracts.length} contracts were found. Multiple were valid.`);
    }
  }

  //If single valid contract was found it is returned with its corresponding
  //tls certification in jwk format
  //If no valid contract was found an error is thrown
  if (validContract) {
    return validAttributes;
  } else {
    throw new Error(`${contracts.length} contracts were found. None was valid.`);
  }
}

/**
 * Builds DID document
 *
 * @param {string} did - TLS DID
 * @param {Attribute []} attributes - The attributes of the DID document
 *
 * @returns {DIDDocument}
 */
function buildDIDDocument(did: string, attributes: Attribute[]): DIDDocument {
  //Set context and subject
  let didDocument: DIDDocument = {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
    publicKey: [],
  };

  //Set attributes by appending attribute values to the DID Document object
  attributes.forEach((attribute) => addValueAtPath(didDocument, attribute.path, attribute.value));

  return didDocument;
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
  parsed: ParsedDID,
  config: ProviderConfig = {},
  registryAddress: string = REGISTRY,
  rootCertificates: readonly string[] = nodeRootCertificates
): Promise<DIDDocument> {
  const provider = configureProvider(config);
  const domain = parsed.id;
  const contracts = await getContracts(domain, provider, registryAddress);
  if (contracts.length === 0) {
    throw new Error('No contract was found');
  }

  const attributes = await processContracts(domain, contracts, rootCertificates);

  return buildDIDDocument(did, attributes);
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
  async function resolve(did: string, parsed: ParsedDID): Promise<DIDDocument> {
    return await resolveTlsDid(did, parsed ? parsed : parse(did), config, registryAddress, rootCertificates);
  }
  return { tls: resolve };
}
