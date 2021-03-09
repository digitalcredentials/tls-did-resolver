import { pki } from 'node-forge';
import { providers } from 'ethers';
import { Attribute, ProviderConfig } from './types';
/**
 * Verifies if signature is correct
 *
 * @param {string} pemCert - public pem certificate
 * @param {string} signature - signature of data signed with private pem certificate
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
 * @param {string[][]} chains - TLS DID Contract certificate chains
 */
export declare function hashContract(domain: string, address: string, attributes?: Attribute[], expiry?: Date, chains?: string[][]): string;
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
/**
 * Splits string of pem keys to array of pem keys
 * @param {string} chain - String of aggregated pem certs
 * @return {string[]} - Array of pem cert string
 */
export declare function chainToCerts(chain: string): string[];
/**
 * Creates node-forge CA certificate store from an string array of CA certificates
 * @param {string[]} rootCertificates - Array of of aggregated pem certs strings
 * @return {pki.CAStore} - node-forge CA certificate store
 */
export declare function createCaStore(rootCertificates: readonly string[]): pki.CAStore;
/**
 * Verifies pem cert chains against node-forge CA certificate store and a domain
 * @param {string[]} chain - Array of of aggregated pem certs strings
 * @param {string} domain - Domain the leaf certificate should have as subject
 * @param {pki.CAStore} caStore - node-forge CA certificate store
 * @return {string[]} - Array of valid chains
 */
export declare function verifyChains(chains: string[][], domain: string, caStore: pki.CAStore): Promise<string[][]>;
/**
 * Checks OCSP
 * @param {string} cert - Website cert in pem format
 * @param {string} issuerCert - Cert of issuer in pem format
 *
 * @returns {Promise<boolean>} - True if valid
 */
export declare function checkOCSP(cert: string, issuerCert: string): Promise<boolean>;
/**
 * Checks for OCSP
 * @param {string} cert - Website cert in pem format
 *
 * @returns {Promise<boolean>} - True if available
 */
export declare function checkForOCSPUri(cert: pki.Certificate): string | null;
