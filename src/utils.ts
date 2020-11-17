import crypto from 'crypto';
import { JWK, JWKRSAKey } from 'jose';
import { readFileSync } from 'fs';
import { providers } from 'ethers';
import SSLCertificate from 'get-ssl-certificate';
import hash from 'object-hash';
import { Attribute, ProviderConfig, ServerCert } from './types';

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
 * Gets pem certificate from server
 *
 * @param {string} did - TLS DID
 */
export async function getCertFromServer(did: string): Promise<ServerCert> {
  const domain = did.substring(8);
  return await SSLCertificate.get(domain);
}

/**
 * Gets pem certificate for debugging purposes
 */
export function debugCert(): string {
  const pemPath = '/../src/__tests__/ssl/certs/testserver.pem';
  return readFileSync(__dirname + pemPath, 'utf8');
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
