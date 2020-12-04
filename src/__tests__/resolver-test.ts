import { readFileSync } from 'fs';
import { getResolver } from '../index';
import { TLSDID } from 'tls-did';
import c from './testConfig.json';

let resolver: { tls: (did: any) => Promise<object> };
let tlsDid: TLSDID;

let cert: string;
let intermidiateCert: string;

const domain = `tls-did.de`;

describe('Resolver', () => {
  beforeAll(async () => {
    cert = readFileSync(__dirname + c.certPath, 'utf8');
    intermidiateCert = readFileSync(__dirname + c.intermediateCertPath, 'utf8');
    const pemKey = readFileSync(__dirname + c.privKeyPath, 'utf8');

    resolver = getResolver();

    tlsDid = new TLSDID(pemKey, c.etherPrivKey, {
      registry: c.registryAddress,
      certRegistry: c.certRegistryAddress,
      providerConfig: {
        rpcUrl: c.jsonRpcUrl,
      },
    });
    await tlsDid.deployContract();
    const random = Math.random().toString(36).substring(7);

    console.log('Registering contract with domain:', tlsDid.domain);
    await tlsDid.registerContract(domain);
    const chain = [cert, intermidiateCert];
    await tlsDid.registerChain(chain);
    await tlsDid.setExpiry(new Date('2040/12/12'));
  });
  it('should resolve did', async () => {
    const didDocument = await resolver.tls(`did:tls:${tlsDid.domain}`);
    //TODO improve testing
    expect(didDocument).toBeTruthy();
  });
});
