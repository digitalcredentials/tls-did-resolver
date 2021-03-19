import { rootCertificates as nodeRootCertificates } from 'tls';
import { Contract, Event } from 'ethers';
import {
  Attribute,
  ProviderConfig,
  configureProvider,
  hashContract,
  verify,
  REGISTRY,
} from '@digitalcredentials/tls-did-utils';
import { addValueAtPath, chainToCerts, createCaStore, verifyChain } from './utils';
import { DIDDocument, DIDResolver, ParsedDID, parse } from 'did-resolver';
import { getClaimants, newRegistry, resolveClaimant } from './chain';
import { pki } from 'node-forge';

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
  const domain = parsed.id;
  const provider = configureProvider(config);
  const registry = await newRegistry(provider, registryAddress);
  const claimants = await getClaimants(registry, domain);
  const attributes = await resolveClaims(rootCertificates, registry, domain, claimants);

  return buildDIDDocument(did, attributes);
}

async function resolveClaims(
  rootCertificates: readonly string[],
  registry: Contract,
  domain: string,
  claimants: string[]
): Promise<Attribute[]> {
  //Create node-forge CA certificate store
  const caStore = createCaStore(rootCertificates);
  let validAttributes: Attribute[] = [];
  let docValid = false;
  for (let claimant of claimants) {
    const events = await resolveClaimant(registry, domain, claimant);
    if (events.length === 0) {
      //No change events found for claimant
      continue;
    }

    let { docObject, valid } = processEvents(events, domain, caStore);
    if (!docObject.chain) {
      //No chain change events found for claimant
      continue;
    }

    if (valid) {
      //Hash contract values
      const hash = hashContract(domain, docObject.attributes, docObject.expiry, docObject.chain);

      //Check for correct signature
      valid = verify(docObject.chain[0], docObject.signature, hash);
      if (!valid) {
        //Signatures does not match data
        continue;
      }
    }
    if (valid && docValid) {
      throw new Error(`did:tls:${domain} could not be unambiguously resolved`);
    }
    if (valid) {
      docValid = true;
      validAttributes = docObject.attributes;
    }
  }
  if (!docValid) {
    throw new Error(`did:tls:${domain} could not be validly resolved`);
  }

  return validAttributes;
}

function processEvents(
  events: Event[],
  domain: string,
  caStore: pki.CAStore
): { docObject: { attributes: Attribute[]; signature: string; expiry: Date; chain: string[] }; valid: boolean } {
  let attributes = [];
  let signature;
  let expiry;
  let chain;
  let invalid = false;

  for (let event of events) {
    switch (true) {
      case event.event == 'AttributeChanged':
        const path = event.args.path;
        const value = event.args.value;
        attributes.push({ path, value });
        break;

      case event.event == 'ExpiryChanged' && expiry == null:
        const expiryMS = event.args.expiry.toNumber();
        expiry = new Date(expiryMS);
        const now = new Date();
        if (expiry && expiry < now) {
          invalid = true;
          continue;
        }
        break;

      case event.event == 'SignatureChanged' && signature == null:
        signature = event.args.signature;
        break;

      case event.event == 'ChainChanged' && chain == null:
        chain = chainToCerts(event.args.chain);
        const chainValid = verifyChain(chain, domain, caStore);
        if (!chainValid) {
          invalid = true;
          continue;
        }
        break;
    }
  }

  return { docObject: { attributes, signature, expiry, chain }, valid: !invalid };
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
