import { rootCertificates } from 'tls';
import { pki } from 'node-forge';
import crypto from 'crypto';
import { JWK, JWKRSAKey } from 'jose';
import { providers } from 'ethers';
import hash from 'object-hash';
import { Attribute, ProviderConfig } from './types';

export function verifyCertificateChain() {
  console.log(rootCertificates);
}

/**
 * Verfies if signature is correct
 *
 * @param {string} pemCert - public pem certificate
 * @param {string} signature - signature of data signiged with private pem certificate
 * @param {string} data - data that has been signed
 */
export function verify(pemCert: string, signature: string, data: string): boolean {
  const signatureBuffer = Buffer.from(signature, 'base64');
  const verifier = crypto.createVerify('sha256');
  verifier.update(data);
  verifier.end();
  const valid = verifier.verify(pemCert, signatureBuffer);
  return valid;
}

/**
 * Hashes a TLS DID Contract
 *
 * @param {string} domain - TLS DID domain
 * @param {string} address - TLS DID Contract address
 * @param {Attribute[]} attributes - Additional TLS DID Documents attributes
 * @param {Date} expiry - TLS DID Contract expiry
 */
export function hashContract(domain: string, address: string, attributes?: Attribute[], expiry?: Date): string {
  return hash({ domain, address, attributes, expiry });
}

/**
 * Transforms x509 pem certificate to JWKRSAKey
 *
 * @param {string} cert
 */
export function x509ToJwk(cert: string): JWKRSAKey {
  return <JWKRSAKey>JWK.asKey(cert).toJWK();
}

/**
 * Adds a value at a path to an object
 *
 * @param object - Object to which the value is added
 * @param {string} path - Path of value. Exp. 'parent/child' or 'parent[]/child'
 * @param {string} value - Value stored in path
 */
export function addValueAtPath(object: object, path: string, value: any) {
  const pathArr = path.split('/');
  let currentObj = object;

  pathArr.forEach((key, index) => {
    if (index === pathArr.length - 1) {
      if (key.endsWith('[]')) {
        key = key.slice(0, -2);
        if (currentObj[key]) {
          currentObj[key].push(value);
        } else {
          currentObj[key] = [value];
        }
      } else {
        currentObj[key] = value;
      }
    } else if (key.endsWith('[]')) {
      key = key.slice(0, -2);
      if (currentObj[key]) {
        currentObj[key].push({});
        currentObj = currentObj[key][currentObj[key].length - 1];
      } else {
        currentObj[key] = [{}];
        currentObj = currentObj[key][0];
      }
    } else {
      currentObj[key] = {};
      currentObj = currentObj[key];
    }
  });
}

/**
 * Returns the configured provider
 * @param {ProviderConfig} conf - Configuration for provider
 */
export function configureProvider(conf: ProviderConfig = {}): providers.Provider {
  if (conf.provider) {
    return conf.provider;
  } else if (conf.rpcUrl) {
    return new providers.JsonRpcProvider(conf.rpcUrl);
  } else if (conf.web3) {
    return new providers.Web3Provider(conf.web3.currentProvider);
  } else {
    return new providers.JsonRpcProvider('http://localhost:8545');
  }
}

/**
 * Splits string of pem keys to array of pem keys
 * @param {string} chain - String of aggregated pem certs
 * @return {string[]} - Array of pem cert string
 */
export function chainToCerts(chain: string): string[] {
  return chain.split(/\n(?=-----BEGIN CERTIFICATE-----)/g);
}

/**
 * Verifies pem cert chains against node's rootCertificates and domain
 * @param {string[]} chain - Array of of aggregated pem certs strings
 * @param {string} domain - Domain the leaf certificat should have as subject
 * @return { chain: string; valid: boolean }[] - Array of objects containing chain and validity
 */
export function processChains(chains: string[], domain: string): { chain: string[]; valid: boolean }[] {
  //Create caStore from node's rootCertificates
  //TODO Add support for EC certs
  console.log('No Support for EC root certs');
  let unsupportedRootCertIdxs = [];
  const pkis = rootCertificates.map((cert, idx) => {
    try {
      return pki.certificateFromPem(cert);
    } catch {
      unsupportedRootCertIdxs.push(idx);
    }
  });
  console.log('unsupportedRootCertIdxs', unsupportedRootCertIdxs);
  const definedPkis = pkis.filter((pki) => pki !== undefined);
  const caStore = pki.createCaStore(definedPkis);

  //Verify each chain against the caStore and domain
  const verifiedChains = chains.map((chain) => {
    const pemArray = chainToCerts(chain);
    return verifyChain(pemArray, domain, caStore);
  });
  return verifiedChains;
}

/**
 * Verifies pem cert chains against node's rootCertificates and domain
 * @param {string[]} chain - Array of of aggregated pem certs strings
 * @param {string} domain - Domain the leaf certificat should have as subject
 * @param {pki.CAStore} caStore - Nodes root certificates in a node-forge compliant format
 * @return { chain: string; valid: boolean }[] - Array of objects containing chain and validity
 */
function verifyChain(chain: string[], domain: string, caStore: pki.CAStore): { chain: string[]; valid: boolean } {
  const certificateArray = chain.map((pem) => pki.certificateFromPem(pem));
  const valid = pki.verifyCertificateChain(caStore, certificateArray) && verifyCertSubject(chain[0], domain);
  return { chain, valid };
}

/**
 * Verifies that the subject of a x509 certificate
 * @param {string} cert - Website cert in pem format
 * @param {string} subject
 */
function verifyCertSubject(cert: string, subject: string): boolean {
  const pkiObject = pki.certificateFromPem(cert);
  //TODO unclear if multiple subjects can be present in x509 certificate
  //https://www.tools.ietf.org/html/rfc5280#section-4.1.2.6
  return pkiObject.subject?.attributes[0]?.value === subject;
}
