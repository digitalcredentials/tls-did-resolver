import { pki } from 'node-forge';
/**
 * Adds a value at a path to an object
 *
 * @param object - Object to which the value is added
 * @param {string} path - Path of value. Exp. 'parent/child' or 'parent[]/child'
 * @param {string} value - Value stored in path
 */
export declare function addValueAtPath(object: object, path: string, value: any): void;
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
 * @typedef {Object} Chain
 * @property {chain} string - The chain
 * @property {boolean} valid - The chain's validity
 */
/**
 * Verifies pem cert chains against node's rootCertificates and domain
 * @param {string[]} chain - Array of of aggregated pem certs strings
 * @param {string} domain - Domain the leaf certificate should have as subject
 * @param {pki.CAStore} caStore - Nodes root certificates in a node-forge compliant format
 * @return {Chain}[] - Array of objects containing chain and validity
 */
export declare function verifyChain(chain: string[], domain: string, caStore: pki.CAStore): Promise<{
    valid: boolean;
}>;
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
