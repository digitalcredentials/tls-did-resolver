import { rootCertificates } from 'tls';
import crypto from 'crypto';
import { pki } from 'node-forge';
import { readFileSync } from 'fs';
import { verify, x509ToJwk, hashContract, addValueAtPath, processChains, checkForOCSPUri, checkOCSP } from '../utils';
import verificationJwk from './ssl/certs/tls-did-de-jwk.json';

const keyPath = '/ssl/private/privKey.pem';
const certPath = '/ssl/certs/cert.pem';
const certRevokedPath = '/ssl/certs/certRevoked.pem';
const intermidiateCertPath = '/ssl/certs/intermediateCert.pem';
let privKey: string;
let cert: string;
let certRevoked: string;
let intermidiateCert: string;

//TODO import from tls-did
function sign(privKey, data) {
  const signer = crypto.createSign('sha256');
  signer.update(data);
  signer.end();
  const signature = signer.sign(privKey).toString('base64');
  return signature;
}

describe('Utlis', () => {
  beforeAll(() => {
    privKey = readFileSync(__dirname + keyPath, 'utf8');
    cert = readFileSync(__dirname + certPath, 'utf8');
    certRevoked = readFileSync(__dirname + certRevokedPath, 'utf8');
    intermidiateCert = readFileSync(__dirname + intermidiateCertPath, 'utf8');
  });

  it('should encrypt and decrypt object with undefined values', async () => {
    const hash = hashContract('example.org', '0xdC2c16ccC8291c43B83D24E37900A3bed3EEd408');
    const signature = sign(privKey, hash);
    const valid = verify(cert, signature, hash);
    expect(valid).toBeTruthy();
  });

  it('should encrypt and decrypt full object', async () => {
    const hash = hashContract(
      'example.org',
      '0xdC2c16ccC8291c43B83D24E37900A3bed3EEd408',
      [{ path: 'parent/child', value: 'value' }],
      new Date()
    );
    const signature = sign(privKey, hash);
    const valid = verify(cert, signature, hash);
    expect(valid).toBeTruthy();
  });

  it('should transform x509 certificate to jwk', async () => {
    const jwk = x509ToJwk(cert);
    expect(jwk).toEqual(verificationJwk);
  });

  it('should add value to object in path', async () => {
    let object = {};
    const path = 'parent/child';
    const value = 'value';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ parent: { child: 'value' } });
  });

  it('should add value to object in path with array', async () => {
    let object = {};
    const path = 'parent[]/child';
    const value = 'value';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ parent: [{ child: 'value' }] });
  });

  it('should add value to object in path with existing array', async () => {
    let object = { parent: [{ childA: 'valueA' }] };
    const path = 'parent[]/childB';
    const value = 'valueB';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ parent: [{ childA: 'valueA' }, { childB: 'valueB' }] });
  });

  it('should add value to array in path', async () => {
    let object = {};
    const path = 'array[]';
    const value = 'valueA';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ array: ['valueA'] });
  });

  it('should add value to array in path with existing array', async () => {
    let object = { array: ['valueA'] };
    const path = 'array[]';
    const value = 'valueB';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ array: ['valueA', 'valueB'] });
  });

  it('should verify pem certificate', async () => {
    const chain = cert + '\n' + intermidiateCert;
    const validChains = await processChains([chain], 'tls-did.de', rootCertificates);
    expect(validChains.length).toEqual(1);
    expect(validChains[0][0]).toEqual(cert);
    expect(validChains[0][1]).toEqual(intermidiateCert);
  });

  it('should check if ocsp is available', async () => {
    const pkiCert = pki.certificateFromPem(cert);
    const response = await checkForOCSPUri(pkiCert);
    expect(response).toBeTruthy();
  });

  it('should verify ocsp status', async () => {
    const responseA = await checkOCSP(cert, intermidiateCert);
    expect(responseA).toBeTruthy();

    const responseB = await checkOCSP(certRevoked, intermidiateCert);
    expect(responseB).toBeFalsy();
  });
});
