import { rootCertificates } from 'tls';
import crypto from 'crypto';
import { pki } from 'node-forge';
import { readFileSync } from 'fs';
import { addValueAtPath, verifyChains, checkForOCSPUri, checkOCSP, chainToCerts, createCaStore } from '../utils';

const keyPath = '/ssl/private/privKey.pem';
const certPath = '/ssl/certs/cert.pem';
const certRevokedPath = '/ssl/certs/certRevoked.pem';
const intermediateCertPath = '/ssl/certs/intermediateCert.pem';
const intermediateRevokedCertPath = '/ssl/certs/intermediateRevokedCert.pem';
let privKey: string;
let cert: string;
let certRevoked: string;
let intermediateCert: string;
let intermediateRevokedCert: string;

describe('Utils', () => {
  beforeAll(() => {
    privKey = readFileSync(__dirname + keyPath, 'utf8');
    cert = readFileSync(__dirname + certPath, 'utf8');
    certRevoked = readFileSync(__dirname + certRevokedPath, 'utf8');
    intermediateCert = readFileSync(__dirname + intermediateCertPath, 'utf8');
    intermediateRevokedCert = readFileSync(__dirname + intermediateRevokedCertPath, 'utf8');
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
    const path = 'parent[0]/child';
    const value = 'value';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ parent: [{ child: 'value' }] });
  });

  it('should add value to object in path with existing object with child', async () => {
    let object = { parent: { childA: 'valueA' } };
    const path = 'parent/childB';
    const value = 'valueB';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ parent: { childA: 'valueA', childB: 'valueB' } });
  });

  it('should add value to object in path with existing array', async () => {
    let object = { parent: [{ childA: 'valueA' }] };
    const path = 'parent[1]/childB';
    const value = 'valueB';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ parent: [{ childA: 'valueA' }, { childB: 'valueB' }] });
  });

  it('should add value to array in path', async () => {
    let object = {};
    const path = 'array[0]';
    const value = 'valueA';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ array: ['valueA'] });
  });

  it('should add value to array in path with existing array', async () => {
    let object = { array: ['valueA'] };
    const path = 'array[1]';
    const value = 'valueB';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ array: ['valueA', 'valueB'] });
  });

  it('should add value to object in existing array', async () => {
    let object = { array: [{ keyA: 'valueA' }] };
    const path = 'array[0]/keyB';
    const value = 'valueB';
    addValueAtPath(object, path, value);
    expect(object).toEqual({ array: [{ keyA: 'valueA', keyB: 'valueB' }] });
  });

  it('should split concatenated certs to array', async () => {
    const concatenatedChain = cert + '\n' + intermediateCert;
    const chains = await chainToCerts(concatenatedChain);
    expect(chains).toEqual([cert, intermediateCert]);
  });

  it('should verify pem certificate', async () => {
    const chain = [cert, intermediateCert];
    const caStore = createCaStore(rootCertificates);
    const validChains = await verifyChains([chain], 'tls-did.de', caStore);
    expect(validChains.length).toEqual(1);
    expect(validChains[0][0]).toEqual(cert);
    expect(validChains[0][1]).toEqual(intermediateCert);
  });

  it('should check if ocsp is available', async () => {
    const pkiCert = pki.certificateFromPem(cert);
    const response = await checkForOCSPUri(pkiCert);
    expect(response).toBeTruthy();
  });

  it('should verify ocsp status', async () => {
    const responseA = await checkOCSP(cert, intermediateCert);
    expect(responseA).toBeTruthy();

    const responseB = await checkOCSP(certRevoked, intermediateRevokedCert);
    expect(responseB).toBeFalsy();
  });
});
