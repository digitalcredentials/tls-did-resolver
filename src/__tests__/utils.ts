import crypto from 'crypto';
import { readFileSync } from 'fs';
import { verify, x509ToJwk, getCertFromServer, hashContract } from '../utils';
import verificationJwk from './ssl/certs/tls-did-de-jwk.json';

const pemKeyPath = '/ssl/private/testserver.pem';
const pemCertPath = '/ssl/certs/testserver.pem';
let pemKey: string;
let pemCert: string;

//TODO import from tls-did
function sign(pemKey, data) {
  const signer = crypto.createSign('sha256');
  signer.update(data);
  signer.end();
  const signature = signer.sign(pemKey).toString('base64');
  return signature;
}

describe('Utlis', () => {
  beforeAll(() => {
    pemKey = readFileSync(__dirname + pemKeyPath, 'utf8');
    pemCert = readFileSync(__dirname + pemCertPath, 'utf8');
  });

  it('should encrypt and decrypt object with undefined values', async () => {
    const hash = hashContract('example.org', '0xdC2c16ccC8291c43B83D24E37900A3bed3EEd408');
    const signature = sign(pemKey, hash);
    const valid = verify(pemCert, signature, hash);
    expect(valid).toBeTruthy();
  });

  it('should encrypt and decrypt full object', async () => {
    const hash = hashContract(
      'example.org',
      '0xdC2c16ccC8291c43B83D24E37900A3bed3EEd408',
      [{ path: 'parent/child', value: 'value' }],
      new Date()
    );
    const signature = sign(pemKey, hash);
    const valid = verify(pemCert, signature, hash);
    expect(valid).toBeTruthy();
  });

  it('should transform x509 certificate to jwk', async () => {
    const serverCert = await getCertFromServer('did:tls:tls-did.de');
    const jwk = x509ToJwk(serverCert.pemEncoded);
    expect(jwk).toEqual(verificationJwk);
  });
});
