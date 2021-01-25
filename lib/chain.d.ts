import { Contract, providers } from 'ethers';
import { Attribute } from './types';
export declare const REGISTRY = "0xA725A297b0F81c502df772DBE2D0AEb68788679d";
/**
 * Gets all TLSDIDContracts associated with a TLS-DID as ethers contract objects
 *
 * @param {string} did - TLS DID
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Promise<Contract>}
 */
export declare function getContracts(domain: string, provider: providers.Provider, registryAddress: string): Promise<Contract[]>;
/**
 * Gets domain from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<String>} - Domain
 */
export declare function getDomain(contract: any): Promise<String>;
/**
 * Gets expiry from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<Date>} - Expiry
 */
export declare function getExpiry(contract: any): Promise<Date>;
/**
 * Gets attributes from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<Attribute[]>} - Attribute Array
 */
export declare function getAttributes(contract: any): Promise<Attribute[]>;
/**
 * Gets chains from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<string[][]>} - Array of chain arrays
 */
export declare function getChains(contract: any): Promise<string[][]>;
/**
 * Gets signature from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<string>} - Signature
 */
export declare function getSignature(contract: any): Promise<string>;
