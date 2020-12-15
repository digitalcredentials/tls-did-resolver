import { readFileSync } from 'fs';
import tls from '../index';
import { TLSDID } from 'tls-did';
import { Resolver, DIDResolver } from 'did-resolver';
import c from './testConfig.json';

let tlsResolver: { [index: string]: DIDResolver };
let tlsDid: TLSDID;

let cert: string;
let intermediateCert: string;

const domain = `tls-did.de`;

describe('Resolver', () => {
  beforeAll(async () => {
    cert = readFileSync(__dirname + c.certPath, 'utf8');
    intermediateCert = readFileSync(__dirname + c.intermediateCertPath, 'utf8');
    const rootCert = readFileSync(__dirname + c.rootCertPath, 'utf8');
    tlsResolver = tls.getResolver(null, c.registryAddress, [rootCert]);

    const pemKey = readFileSync(__dirname + c.privKeyPath, 'utf8');
    tlsDid = new TLSDID(pemKey, c.etherPrivKey, {
      registry: c.registryAddress,
      providerConfig: {
        rpcUrl: c.jsonRpcUrl,
      },
    });
    await tlsDid.deployContract();
    const random = Math.random().toString(36).substring(7);

    await tlsDid.registerContract(domain);
    const chain = [cert, intermediateCert];
    await tlsDid.registerChain(chain);
    await tlsDid.setExpiry(new Date('2040/12/12'));
  });
  it('should resolve did', async () => {
    const didDocument = await tlsResolver.tls(`did:tls:${tlsDid.domain}`, null, null);
    //TODO improve testing
    expect(didDocument).toBeTruthy();
  });

  it('should resolve did with universal resolver', async () => {
    const resolver = new Resolver({ ...tlsResolver });
    const didDocument = await resolver.resolve(`did:tls:${tlsDid.domain}`);
    //TODO improve testing
    expect(didDocument).toBeTruthy();
  });
});
