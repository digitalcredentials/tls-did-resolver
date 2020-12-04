import { ProviderConfig, Resolver } from './types';
export declare const REGISTRY = "0xA725A297b0F81c502df772DBE2D0AEb68788679d";
export declare const CERT_REGISTRY = "0xBCC29C38aeA44A3B6576bF6fed8584BE63A910ac";
/**
 * Gets TLS DID Resolver
 *
 * @param {ProviderConfig} config - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Resolver}
 */
export declare function getResolver(config?: ProviderConfig, registryAddress?: string): Resolver;
