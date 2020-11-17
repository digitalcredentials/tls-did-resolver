import { ProviderConfig, Resolver } from './types';
export declare const REGISTRY = "0x33fD81799f172C8C932C9a3Fbc7dda9cdE26880A";
/**
 * Gets TLS DID Resolver
 *
 * @param {ProviderConfig} config - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Resolver}
 */
export declare function getResolver(config?: ProviderConfig, registryAddress?: string): Resolver;
