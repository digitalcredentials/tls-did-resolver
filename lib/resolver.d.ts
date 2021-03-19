import { ProviderConfig } from '@digitalcredentials/tls-did-utils';
import { DIDResolver } from 'did-resolver';
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
