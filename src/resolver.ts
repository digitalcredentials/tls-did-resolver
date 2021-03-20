import { rootCertificates as nodeRootCertificates } from 'tls';
import { pki } from 'node-forge';
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
import { TLSDIDResolverError } from './error';

/**
 * Gets TLS DID Resolver
 *
 * @param {ProviderConfig} config - Ethereum provider
 * @param {string} registryAddress - Address of TLS-DID Registry
 * @param {string[]} rootCertificates - Trusted TLS root certificates
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
 * @param {ParsedDID} parsed - Parsed DID
 * @param {ProviderConfig} config - Configuration for ethereum provider
 * @param {string} registryAddress - Address of TLS-DID Registry
 * @param {string[]} rootCertificates - Trusted TLS root certificates
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
  if (domain?.length === 0) {
    throw new Error(`TLS-DID could not be validly resolved. No domain provided`);
  }

  //Configure ethereum provider and TLS-DID registry contract object
  const provider = configureProvider(config);
  const registry = await newRegistry(provider, registryAddress);

  //Read set of claimants for TLS-DID identifier (domain) from chain
  const claimants = await getClaimants(registry, domain);
  if (claimants.length === 0) {
    throw new Error(`did:tls:${domain} could not be validly resolved. No claimants could be found`);
  }

  //Resolve all claimants for TLS-DID identifier (domain)
  //If exactly one valid claim is found a set of attributes for the TLS-DID Document is returned
  const attributes = await resolveClaimants(rootCertificates, registry, domain, claimants);

  return buildDIDDocument(did, attributes);
}

/**
 * Resolves all claimants
 *
 * @param {string[]} rootCertificates - Trusted TLS root certificates
 * @param {Contract} registry - TLS-DID registry contract object
 * @param {string} domain - TLS-DID identifier (domain)
 * @param {string[]} claimants - Set of ethereum addresses claiming control over TLS-DID
 *
 * @returns {Promise<DIDDocumentObject>}
 */
async function resolveClaimants(
  rootCertificates: readonly string[],
  registry: Contract,
  domain: string,
  claimants: string[]
): Promise<Attribute[]> {
  //Create node-forge CA certificate store
  const caStore = createCaStore(rootCertificates);

  let validAttributes: Attribute[] = [];
  let docValid = false;
  let errors: { claimant: string; error: Error }[] = [];
  for (const [i, claimant] of claimants.entries()) {
    let events;
    try {
      events = await resolveClaimant(registry, domain, claimant);
    } catch (error) {
      errors[i] = { claimant, error };
      continue;
    }

    if (events.length === 0) {
      //No change events found for claimant
      errors[i] = { claimant, error: new Error('No events') };
      continue;
    }

    let attributes;
    try {
      attributes = processEvents(events, domain, caStore);
    } catch (error) {
      errors[i] = { claimant, error };
      continue;
    }

    if (docValid) {
      throw new Error(
        `did:tls:${domain} could not be unambiguously resolved. ${claimants.length} claimants exist, at least two have a valid claim.`
      );
    }
    docValid = true;
    validAttributes = attributes;
  }
  if (!docValid) {
    throw new TLSDIDResolverError(`did:tls:${domain} could not be validly resolved`, errors);
  }

  return validAttributes;
}

/**
 * Iterates thru events to validate TLS-DID
 *
 * @param {Event[]} events - Set of events
 * @param {string} domain - TLS-DID identifier (domain)
 * @param {pki.CAStore} caStore - node-forge CA certificate store
 *
 * @returns {Attribute[]} - Set off TLS-DID attributes
 */
function processEvents(events: Event[], domain: string, caStore: pki.CAStore): Attribute[] {
  let attributes: Attribute[] = [];
  let signature: string;
  let expiry: Date;
  let chain: string[];

  for (let event of events) {
    switch (true) {
      case event.event == 'AttributeChanged':
        const path = event.args.path;
        const value = event.args.value;
        attributes.unshift({ path, value });
        break;

      case event.event == 'ExpiryChanged' && expiry == null:
        const expiryMS = event.args.expiry.toNumber();
        expiry = new Date(expiryMS);
        const now = new Date();
        if (expiry && expiry < now) {
          throw new Error('TLS-DID expired');
        }
        break;

      case event.event == 'SignatureChanged' && signature == null:
        signature = event.args.signature;
        break;

      case event.event == 'ChainChanged' && chain == null:
        chain = chainToCerts(event.args.chain);
        const chainValid = verifyChain(chain, domain, caStore);
        if (!chainValid) {
          throw new Error('TLS certificate chain invalid');
        }
        break;
    }
  }

  if (!chain) {
    //No chain change events found for claimant
    throw new Error('No TLS certificate chain');
  }

  //Hash contract values
  const hash = hashContract(domain, attributes, expiry, chain);

  //Check for correct signature
  let signatureValid = verify(chain[0], signature, hash);
  if (!signatureValid) {
    throw new Error('Signature invalid');
  }
  return attributes;
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
