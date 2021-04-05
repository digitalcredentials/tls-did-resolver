import { Contract, providers, EventFilter, Event } from 'ethers';
import { hexZeroPad } from 'ethers/lib/utils';
import TLSDIDRegistryContract from '@digitalcredentials/tls-did-registry/build/contracts/TLSDIDRegistry.json';
import { sortEvents } from '@digitalcredentials/tls-did-utils';

/**
 * Creates TLS-DID registry contract object
 *
 * @param {providers.Provider} provider - Ethereum provider
 * @param {string} registryAddress - Ethereum address of TLS-DID registry contract
 *
 * @returns {Promise<Contract>}
 */
export async function newRegistry(provider: providers.Provider, registryAddress: string): Promise<Contract> {
  //Setup TLS DID registry
  const registry = new Contract(registryAddress, TLSDIDRegistryContract.abi, provider);
  return registry;
}

/**
 * Reads claimants from TLS-DID registry contract
 *
 * @param {Contract} registry - Creates TLS-DID registry contract object
 * @param {string} domain - TLS-DID identifier (domain)
 *
 * @returns {Promise<string[]>}
 */
export async function getClaimants(registry: Contract, domain: string): Promise<string[]> {
  const claimantsCountBN = await registry.getClaimantsCount(domain);
  const claimantsCount = claimantsCountBN.toNumber();
  if (claimantsCount === 0) {
    return [];
  }

  const claimants = await Promise.all(
    Array.from(Array(claimantsCount).keys()).map((i) => registry.claimantsRegistry(domain, i))
  );
  const uniqClaimants = Array.from(new Set(claimants));

  return uniqClaimants;
}

/**
 * Queries events from ethereum chain for a claimant
 *
 * @param {Contract} registry - TLS-DID registry contract object
 * @param {string} domain - TLS-DID identifier (domain)
 * @param {string} address - Ethereum address of claimant
 *
 * @returns {Promise<Event[]>}
 */
export async function resolveClaimant(registry: Contract, domain: string, address: string): Promise<Event[]> {
  const lastChangeBlockBN = await registry.changeRegistry(address, domain);
  const lastChangeBlock = lastChangeBlockBN.toNumber();
  if (lastChangeBlock === 0) {
    return [];
  }

  let filters = [
    registry.filters.ExpiryChanged(),
    registry.filters.SignatureChanged(),
    registry.filters.AttributeChanged(),
    registry.filters.ChainChanged(),
  ];
  filters.forEach((filter) => filter.topics.push(hexZeroPad(address, 32)));

  return await queryChain(registry, filters, lastChangeBlock);
}

/**
 * Queries events from ethereum chain for set of filters starting at block number
 *
 * @param {Contract} registry - TLS-DID registry contract object
 * @param {EventFilter[]} filters - Set of event filters
 * @param {number} block - Block number where the query is started
 *
 * @returns {Promise<Event[]>}
 */
async function queryChain(registry, filters: EventFilter[], block: number): Promise<Event[]> {
  //TODO This could be more efficient, the ethers library only correctly decodes events if event type is present in event filter
  //The block with the last change is search for all types of changed events
  let events = await queryBlock(registry, filters, block);
  if (events.length === 0) {
    throw new Error(`No event found in block: ${block}`);
  }

  //Sort events by descending blocknumber
  events = sortEvents(events);

  //Recursion if previous change block is not 0
  const previousChangeBlockBN = events[events.length - 1].args.previousChange;
  const previousChangeBlock = previousChangeBlockBN.toNumber();
  if (previousChangeBlock > 0) {
    events.push(...(await queryChain(registry, filters, previousChangeBlock)));
  }

  return events;
}

/**
 * Queries events from ethereum chain in block
 *
 * @param {Contract} registry - TLS-DID registry contract object
 * @param {EventFilter[]} filters - Set of event filters
 * @param {number} block - Block number where to query
 *
 * @returns {Promise<Event[]>}
 */
async function queryBlock(registry, filters: EventFilter[], block: number): Promise<Event[]> {
  let events = (await Promise.all(filters.map((filter) => registry.queryFilter(filter, block, block)))).flat();
  return events;
}
