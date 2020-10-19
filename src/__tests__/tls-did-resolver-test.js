import crypto from 'crypto';
import { readFileSync } from 'fs';
import { ethers } from 'ethers';
import Resolver from '../tls-did-resolver';

const jsonRpcUrl = 'http://127.0.0.1:8545';

describe('Resolver', () => {
  const provider = new ethers.providers.JsonRpcProvider(jsonRpcUrl);
  const resolver = new Resolver(provider);

  it('should load did contracts', async () => {
    const contracts = await resolver.resolveDIDSC('did:tls:example.org');

    console.log(contracts);
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
      '0xdC2c16ccC8291c43B83D24E37900A3bed3EEd408'
    );
    const signature = sign(pemKey, hash);
    const valid = verify(pemCert, signature, hash);
    expect(valid).toBeTruthy();
  });
});

function hashContract(domain, address, attributes, expiry) {
  //TODO implement if values are empty/undefined => ""
  //TODO test use buffer?
  const stringified = domain + address + attributes + expiry;
  const hasher = crypto.createHash('sha256');
  hasher.update(stringified);
  const hash = hasher.digest('base64');
  return hash;
}

function sign(pemKey, data) {
  const signer = crypto.createSign('sha256');
  signer.update(data);
  signer.end();
  const signature = signer.sign(pemKey).toString('base64');
  return signature;
}

function verify(pemCert, signature, data) {
  const signatureBuffer = new Buffer.from(signature, 'base64');
  const verifier = crypto.createVerify('sha256');
  verifier.update(data);
  verifier.end();
  const valid = verifier.verify(pemCert, signatureBuffer);
  return valid;
}
