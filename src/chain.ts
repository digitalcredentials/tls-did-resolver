import { Contract, providers, EventFilter, Event } from 'ethers';
import { hexZeroPad } from 'ethers/lib/utils';
import TLSDIDRegistryContract from '@digitalcredentials/tls-did-registry/build/contracts/TLSDIDRegistry.json';

export async function newRegistry(provider: providers.Provider, registryAddress: string): Promise<Contract> {
  //Setup TLS DID registry
  const registry = new Contract(registryAddress, TLSDIDRegistryContract.abi, provider);
  return registry;
}

export async function getClaimants(registry: Contract, domain: string) {
  if (domain?.length === 0) {
    throw new Error('No domain provided');
  }
  const claimantsCountBN = await registry.getClaimantsCount(domain);
  const claimantsCount = claimantsCountBN.toNumber();
  if (claimantsCount === 0) {
    throw new Error(`No claims to did:tls:${domain} contracts were found.`);
  }

  const claimants = await Promise.all(
    Array.from(Array(claimantsCount).keys()).map((i) => registry.claimantsRegistry(domain, i))
  );
  const uniqClaimants = Array.from(new Set(claimants));

  return uniqClaimants;
}

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

async function queryChain(registry, filters: EventFilter[], block: number): Promise<Event[]> {
  //TODO This could be more efficient, the ethers library only correctly decodes events if event type is present in event filter
  //The block with the last change is search for all types of changed events
  let events = await queryBlock(registry, filters, block);
  if (events.length === 0) {
    throw new Error(`No event found in block: ${block}`);
  }

  // TODO is the event array sorted by creation time
  const previousChangeBlockBN = events[events.length - 1].args.previousChange;
  const previousChangeBlock = previousChangeBlockBN.toNumber();
  if (previousChangeBlock > 0) {
    events.push(...(await queryChain(registry, filters, previousChangeBlock)));
  }

  return events;
}

async function queryBlock(registry, filters: EventFilter[], block: number): Promise<Event[]> {
  let events = (await Promise.all(filters.map((filter) => registry.queryFilter(filter, block, block)))).flat();
  return events;
}
