import { BigNumber, Contract, providers } from 'ethers';
import TLSDIDJson from '@digitalcredentials/tls-did-registry/build/contracts/TLSDID.json';
import TLSDIDRegistryContract from '@digitalcredentials/tls-did-registry/build/contracts/TLSDIDRegistry.json';
import { chainToCerts } from './utils';
import { Attribute } from './types';

export const REGISTRY = '0xA725A297b0F81c502df772DBE2D0AEb68788679d';
const NULL_ADDRESS = '0x0000000000000000000000000000000000000000';

/**
 * Gets all TLSDIDContracts associated with a TLS-DID as ethers contract objects
 *
 * @param {string} did - TLS DID
 * @param {providers.JsonRpcProvider} provider - Ethereum provider
 * @param {string} registryAddress - Address of TLS DID Contract Registry
 *
 * @returns {Promise<Contract>}
 */

export async function getContracts(domain: string, provider: providers.Provider, registryAddress: string): Promise<Contract[]> {
  //Setup TLS DID registry
  const registry = new Contract(registryAddress, TLSDIDRegistryContract.abi, provider);

  //Retrieve all addresses stored in the registry for the did
  const addresses: string[] = await registry.getContracts(domain);

  //Create contract objects from addresses
  let contracts = [];
  for (let address of addresses) {
    if (address == NULL_ADDRESS) {
      //DID was deleted
      continue;
    }

    //Create contract object from address.
    contracts.push(new Contract(address, TLSDIDJson.abi, provider));
  }

  return contracts;
}

/**
 * Gets domain from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<String>} - Domain
 */
export async function getDomain(contract): Promise<String> {
  return await contract.domain();
}

/**
 * Gets expiry from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<Date>} - Expiry
 */
export async function getExpiry(contract): Promise<Date> {
  const expiryBN: BigNumber = await contract.expiry();
  return new Date(expiryBN.toNumber());
}

/**
 * Gets attributes from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<Attribute[]>} - Attribute Array
 */
export async function getAttributes(contract): Promise<Attribute[]> {
  const attributeCountBN = await contract.getAttributeCount();
  const attributeCount = attributeCountBN.toNumber();

  //Creates and waits for an array of promises each containing an getAttribute call
  const attributesStrings = await Promise.all(Array.from(Array(attributeCount).keys()).map((i) => contract.getAttribute(i)));

  //Transforms array representation of attributes to object representation
  let attributes = [];
  attributesStrings.forEach((attribute) => {
    const path = attribute['0'];
    const value = attribute['1'];
    attributes.push({ path, value });
  });
  return attributes;
}

/**
 * Gets chains from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<string[][]>} - Array of chain arrays
 */
export async function getChains(contract): Promise<string[][]> {
  const chainCountBN = await contract.getChainCount();
  const chainCount = chainCountBN.toNumber();

  //Creates and waits for an array of promises each containing an getChain call
  const chains = await Promise.all(Array.from(Array(chainCount).keys()).map((i) => contract.getChain(i)));

  //Splits concatenated cert string to array of certs
  return chains.map((chain) => chainToCerts(chain));
}

/**
 * Gets signature from contract
 * @param {Contract} contract - Ethers TLSDID contract object
 *
 * @returns {Promise<string>} - Signature
 */
export async function getSignature(contract): Promise<string> {
  return await contract.signature();
}
