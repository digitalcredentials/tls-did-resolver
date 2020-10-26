import crypto from 'crypto';
import { JWK } from 'jose';
import { readFileSync } from 'fs';
import SSLCertificate from 'get-ssl-certificate';

interface attribute {
  path: string;
  value: string;
}

export function verify(pemCert: string, signature: string, data: string): boolean {
  const signatureBuffer = Buffer.from(signature, 'base64');
  const verifier = crypto.createVerify('sha256');
  verifier.update(data);
  verifier.end();
  const valid = verifier.verify(pemCert, signatureBuffer);
  return valid;
}

//TODO Explore byte array
export function hashContract(domain: string, address: string, attributes?: attribute[], expiry?: number): string {
  let attributeString = '';
  if (attributes) {
    attributes.forEach((attribute) => (attributeString += attribute.path + attribute.value));
  }

  let expiryString = '';
  if (expiry) {
    expiryString = expiry.toString();
  }

  const stringified = domain + address + attributeString + expiryString;
  const hasher = crypto.createHash('sha256');
  hasher.update(stringified);
  const hash = hasher.digest('base64');
  return hash;
}

export async function getCertFromServer(did: string): Promise<string> {
  const domain = did.substring(8);
  const cert = await SSLCertificate.get(domain);
  return cert.pemEncoded;
}

export function debugCert(): string {
  const pemPath = '/__tests__/ssl/certs/testserver.pem';
  const cert = readFileSync(__dirname + pemPath, 'utf8');
  return cert;
}

export function x509ToJwk(cert: string): JWK.RSAKey {
  const jwk = JWK.asKey(cert);
  return <JWK.RSAKey>jwk;
}

export function addValueAtPath(object: object, path: string, value: any) {
  const pathArr = path.split('/');
  let currentObj = object;

  pathArr.forEach((key, index) => {
    if (index === pathArr.length - 1) {
      currentObj[key] = value;
    } else {
      currentObj[key] = {};
      currentObj = currentObj[key];
    }
  });
}
