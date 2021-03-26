import { Contract, providers, Event } from 'ethers';
/**
 * Creates TLS-DID registry contract object
 *
 * @param {providers.Provider} provider - Ethereum provider
 * @param {string} registryAddress - Ethereum address of TLS-DID registry contract
 *
 * @returns {Promise<Contract>}
 */
export declare function newRegistry(provider: providers.Provider, registryAddress: string): Promise<Contract>;
/**
 * Reads claimants from TLS-DID registry contract
 *
 * @param {Contract} registry - Creates TLS-DID registry contract object
 * @param {string} domain - TLS-DID identifier (domain)
 *
 * @returns {Promise<string[]>}
 */
export declare function getClaimants(registry: Contract, domain: string): Promise<string[]>;
/**
 * Queries events from ethereum chain for a claimant
 *
 * @param {Contract} registry - TLS-DID registry contract object
 * @param {string} domain - TLS-DID identifier (domain)
 * @param {string} address - Ethereum address of claimant
 *
 * @returns {Promise<Event[]>}
 */
export declare function resolveClaimant(registry: Contract, domain: string, address: string): Promise<Event[]>;
