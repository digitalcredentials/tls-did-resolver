import { ProviderConfig } from './types';
import { DIDResolver } from 'did-resolver';
export declare const REGISTRY = "0xA725A297b0F81c502df772DBE2D0AEb68788679d";
/**
 * Gets TLS DID Resolver
 *
 * @param {ProviderConfig} config - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Resolver}
 */
export declare function getResolver(config?: ProviderConfig, registryAddress?: string, rootCertificates?: string[]): {
    [index: string]: DIDResolver;
};
