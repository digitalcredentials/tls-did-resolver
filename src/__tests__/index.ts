import crypto from 'crypto';
import { readFileSync } from 'fs';
import { ethers } from 'ethers';
import { Resolver, getResolver, hashContract } from '../index';

const jsonRpcUrl = 'http://127.0.0.1:8545';

describe('Resolver', () => {
  const provider = new ethers.providers.JsonRpcProvider(jsonRpcUrl);
  const resolver = getResolver(provider, undefined);

  it('should load did contracts', async () => {
    const contracts = await resolver.tls('did:tls:example.org');

    //console.log(contracts);
    //  assert.deepEqual(
    //    address,
    //    [address, '0xdC2c16ccC8291c43B83D24E37900A3bed3EEd408'],
    //    'Identical did => address mapping was added'
    //  );
  });

  it('should encrypt and decrypt', async () => {
    const pemKeyPath = '/ssl/private/testserver.pem';
    const pemCertPath = '/ssl/certs/testserver.pem';

    const pemKey = readFileSync(__dirname + pemKeyPath, 'utf8');
    const pemCert = readFileSync(__dirname + pemCertPath, 'utf8');
    const hash = hashContract(
      'example.org',
      '0xdC2c16ccC8291c43B83D24E37900A3bed3EEd408',
      undefined, undefined
    );
    const signature = sign(pemKey, hash);
    const valid = verify(pemCert, signature, hash);
    expect(valid).toBeTruthy();
  });
});

function sign(pemKey, data) {
  const signer = crypto.createSign('sha256');
  signer.update(data);
  signer.end();
  const signature = signer.sign(pemKey).toString('base64');
  return signature;
}

function verify(pemCert, signature, data) {
  const signatureBuffer = Buffer.from(signature, 'base64');
  const verifier = crypto.createVerify('sha256');
  verifier.update(data);
  verifier.end();
  const valid = verifier.verify(pemCert, signatureBuffer);
  return valid;
}
