import { JWKRSAKey } from 'jose';
import { providers } from 'ethers';
import { Attribute, ProviderConfig, ServerCert } from './types';
/**
 * Verfies if signature is correct
 *
 * @param {string} pemCert - public pem certificate
 * @param {string} signature - signature of data signiged with private pem certificate
 * @param {string} data - data that has been signed
 */
export declare function verify(pemCert: string, signature: string, data: string): boolean;
/**
 * Hashes a TLS DID Contract
 *
 * @param {string} domain - TLS DID domain
 * @param {string} address - TLS DID Contract address
 * @param {Attribute[]} attributes - Additional TLS DID Documents attributes
 * @param {Date} expiry - TLS DID Contract expiry
 */
export declare function hashContract(domain: string, address: string, attributes?: Attribute[], expiry?: Date): string;
/**
 * Gets pem certificate from server
 *
 * @param {string} did - TLS DID
 */
export declare function getCertFromServer(did: string): Promise<ServerCert>;
/**
 * Gets pem certificate for debugging purposes
 */
export declare function debugCert(): string;
/**
 * Transforms x509 pem certificate to JWKRSAKey
 *
 * @param {string} cert
 */
export declare function x509ToJwk(cert: string): JWKRSAKey;
/**
 * Adds a value at a path to an object
 *
 * @param object - Object to which the value is added
 * @param {string} path - Path of value. Exp. 'parent/child' or 'parent[]/child'
 * @param {string} value - Value stored in path
 */
export declare function addValueAtPath(object: object, path: string, value: any): void;
/**
 * Returns the configured provider
 * @param {ProviderConfig} conf - Configuration for provider
 */
export declare function configureProvider(conf?: ProviderConfig): providers.Provider;
