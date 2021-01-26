import { pki, asn1 } from 'node-forge';
import crypto from 'crypto';
import { providers } from 'ethers';
import hash from 'object-hash';
import ocsp from 'ocsp';
import { Attribute, ProviderConfig } from './types';

/**
 * Verifies if signature is correct
 *
 * @param {string} pemCert - public pem certificate
 * @param {string} signature - signature of data signed with private pem certificate
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
 * @param {string[][]} chains - TLS DID Contract certificate chains
 */
export function hashContract(
  domain: string,
  address: string,
  attributes: Attribute[] = [],
  expiry: Date = null,
  chains: string[][] = []
): string {
  return hash({ domain, address, attributes, expiry, chains });
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
      if (key.endsWith(']')) {
        const idx = parseInt(key.slice(-2, -1));
        key = key.slice(0, -3);
        if (!currentObj[key]) {
          currentObj[key] = [];
        }
        currentObj[key][idx] = value;
      } else {
        currentObj[key] = value;
      }
    } else if (key.endsWith(']')) {
      const idx = parseInt(key.slice(-2, -1));
      key = key.slice(0, -3);
      if (!currentObj[key]) {
        currentObj[key] = [];
      }
      if (!currentObj[key][idx]) {
        currentObj[key][idx] = {};
      }
      currentObj = currentObj[key][idx];
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
  if (conf?.provider) {
    return conf.provider;
  } else if (conf?.rpcUrl) {
    return new providers.JsonRpcProvider(conf.rpcUrl);
  } else if (conf?.web3) {
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
 * @param {string} domain - Domain the leaf certificate should have as subject
 * @return { chain: string}[] - Array of valid chains
 */
export async function verifyChains(
  chains: string[][],
  domain: string,
  rootCertificates: readonly string[]
): Promise<string[][]> {
  //Filter duplicate chains
  const filteredChains = Array.from(new Set(chains));

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
  let verifiedChains = [];
  for (let chain of filteredChains) {
    if (await verifyChain(chain, domain, caStore)) {
      verifiedChains.push(chain);
    }
  }
  return verifiedChains;
}

/**
 * Verifies pem cert chains against node's rootCertificates and domain
 * @param {string[]} chain - Array of of aggregated pem certs strings
 * @param {string} domain - Domain the leaf certificate should have as subject
 * @param {pki.CAStore} caStore - Nodes root certificates in a node-forge compliant format
 * @return { chain: string; valid: boolean }[] - Array of objects containing chain and validity
 */
async function verifyChain(chain: string[], domain: string, caStore: pki.CAStore): Promise<{ valid: boolean }> {
  const certificateArray = chain.map((pem) => pki.certificateFromPem(pem));
  let valid = pki.verifyCertificateChain(caStore, certificateArray) && verifyCertSubject(chain[0], domain);
  const ocspUri = checkForOCSPUri(certificateArray[0]);
  if (ocspUri) {
    valid = valid && (await checkOCSP(chain[0], chain[1]));
  }
  return { valid };
}

/**
 * Verifies that the subject of a x509 certificate
 * @param {string} cert - Website cert in pem format
 * @param {string} subject
 */
function verifyCertSubject(cert: string, subject: string): boolean {
  const pkiObject = pki.certificateFromPem(cert);
  //TODO unclear if multiple subjects can be present in x509 leaf certificate
  //https://www.tools.ietf.org/html/rfc5280#section-4.1.2.6
  return pkiObject.subject?.attributes[0]?.value === subject;
}

/**
 * Checks OCSP
 * @param {string} cert - Website cert in pem format
 * @param {string} issuerCert - Cert of issuer in pem format
 *
 * @returns {Promise<boolean>} - True if valid
 */
export async function checkOCSP(cert: string, issuerCert: string): Promise<boolean> {
  const response: boolean = await new Promise((resolve, reject) => {
    ocsp.check(
      {
        cert: cert,
        issuer: issuerCert,
      },
      function (err, res) {
        if (!res) reject(err);
        else {
          const valid = res.type === 'good';
          resolve(valid);
        }
      }
    );
  });
  return response;
}

/**
 * Checks for OCSP
 * @param {string} cert - Website cert in pem format
 *
 * @returns {Promise<boolean>} - True if available
 */
export function checkForOCSPUri(cert: pki.Certificate): string | null {
  // Return value type incorrect
  const aIAExtension = cert.getExtension('authorityInfoAccess') as { value: string } | null;
  if (aIAExtension === null) {
    return null;
  }
  const aIAValue = asn1.fromDer(aIAExtension.value);
  let aIAValues = [];
  for (let value of aIAValue.value) {
    const test = <{ certificateExtensionFromAsn1: (asn1: any) => any }>(<unknown>pki);
    aIAValues.push(test.certificateExtensionFromAsn1(value));
  }
  const oscpExtensions = aIAValues.filter((value) => (value.id = '1.3.6.1.5.5.7.48.1'));
  if (oscpExtensions.length === 0) {
    return null;
  }
  return oscpExtensions[0].value;
}
