import { pki, asn1 } from 'node-forge';
import ocsp from 'ocsp';

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
 * Splits string of pem keys to array of pem keys
 * @param {string} chain - String of aggregated pem certs
 * @return {string[]} - Array of pem cert string
 */
export function chainToCerts(chain: string): string[] {
  return chain.split(/\n(?=-----BEGIN CERTIFICATE-----)/g);
}

/**
 * Creates node-forge CA certificate store from an string array of CA certificates
 * @param {string[]} rootCertificates - Array of of aggregated pem certs strings
 * @return {pki.CAStore} - node-forge CA certificate store
 */
export function createCaStore(rootCertificates: readonly string[]): pki.CAStore {
  //Create caStore from node's rootCertificates
  //TODO Add support for EC certs (https://github.com/digitalcredentials/tls-did/issues/27)
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
  return pki.createCaStore(definedPkis);
}

/**
 * Verifies pem cert chains against node-forge CA certificate store and a domain
 * @param {string[]} chain - Array of of aggregated pem certs strings
 * @param {string} domain - Domain the leaf certificate should have as subject
 * @param {pki.CAStore} caStore - node-forge CA certificate store
 * @return {string[]} - Array of valid chains
 */
export async function verifyChains(chains: string[][], domain: string, caStore: pki.CAStore): Promise<string[][]> {
  //Filter duplicate chains
  const filteredChains = Array.from(new Set(chains));

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
 * @return {Chain}[] - Array of objects containing chain and validity
 */
export async function verifyChain(chain: string[], domain: string, caStore: pki.CAStore): Promise<{ valid: boolean }> {
  const certificateArray = chain.map((pem) => pki.certificateFromPem(pem));
  let valid = pki.verifyCertificateChain(caStore, certificateArray) && verifyCertSubject(chain[0], domain);
  const ocspUri = checkForOCSPUri(certificateArray[0]);
  if (ocspUri) {
    valid = valid && (await checkOCSP(chain[0], chain[1]));
  }
  return { valid };
}

/**
 * Verifies the subject of a x509 certificate
 * @param {string} cert - Website cert in pem format
 * @param {string} subject
 */
function verifyCertSubject(cert: string, subject: string): boolean {
  const pkiObject = pki.certificateFromPem(cert);
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
        if (!res) resolve(false);
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
