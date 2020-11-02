import crypto from 'crypto';
import { JWK, JWKRSAKey } from 'jose';
import { readFileSync } from 'fs';
import SSLCertificate from 'get-ssl-certificate';
import hash from 'object-hash';

export function verify(pemCert: string, signature: string, data: string): boolean {
  const signatureBuffer = Buffer.from(signature, 'base64');
  const verifier = crypto.createVerify('sha256');
  verifier.update(data);
  verifier.end();
  const valid = verifier.verify(pemCert, signatureBuffer);
  return valid;
}

//TODO Explore byte array
export function hashContract(domain: string, address: string, attributes?: IAttribute[], expiry?: Date): string {
  return hash({ domain, address, attributes, expiry });
}

export async function getCertFromServer(did: string): Promise<IServerCert> {
  const domain = did.substring(8);
  return await SSLCertificate.get(domain);
}

export function debugCert(): string {
  const pemPath = '/../src/__tests__/ssl/certs/testserver.pem';
  return readFileSync(__dirname + pemPath, 'utf8');
}

export function x509ToJwk(cert: string): JWKRSAKey {
  return <JWKRSAKey>JWK.asKey(cert).toJWK();
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
