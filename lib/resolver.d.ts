import { ProviderConfig } from '@digitalcredentials/tls-did-utils';
import { DIDResolver } from 'did-resolver';
/**
 * Gets TLS DID Resolver
 *
 * @param {ProviderConfig} config - Ethereum provider
 * @param {string} registryAddress - Address of TLS-DID Registry
 * @param {string[]} rootCertificates - Trusted TLS root certificates
 *
 * @returns {Resolver}
 */
export declare function getResolver(config?: ProviderConfig, registryAddress?: string, rootCertificates?: string[]): {
    [index: string]: DIDResolver;
};
