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
    //Load certs and key
    cert = readFileSync(__dirname + c.certPath, 'utf8');
    intermediateCert = readFileSync(__dirname + c.intermediateCertPath, 'utf8');
    const rootCert = readFileSync(__dirname + c.rootCertPath, 'utf8');
    const pemKey = readFileSync(__dirname + c.privKeyPath, 'utf8');

    //Instantiate resolver
    tlsResolver = tls.getResolver(null, c.registryAddress, [rootCert]);

    //Instantiate tlsDid
    tlsDid = new TLSDID(c.etherPrivKey, {
      registry: c.registryAddress,
      providerConfig: {
        rpcUrl: c.jsonRpcUrl,
      },
    });

    //Deploy & fill tls did smart contract with data
    await tlsDid.deployContract();
    await tlsDid.registerContract(domain, pemKey);
    const chain = [cert, intermediateCert];
    await tlsDid.addChain(chain, pemKey);
    await tlsDid.setExpiry(new Date('2040/12/12'), pemKey);
  });

  it('should resolve did', async () => {
    const didDocument = await tlsResolver.tls(`did:tls:${tlsDid.domain}`, null, null);

    expect(didDocument).toEqual({
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:tls:tls-did.de',
      publicKey: [],
    });
  });

  it('should resolve did with universal resolver', async () => {
    const resolver = new Resolver({ ...tlsResolver });
    const didDocument = await resolver.resolve(`did:tls:${tlsDid.domain}`);

    expect(didDocument).toEqual({
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:tls:tls-did.de',
      publicKey: [],
    });
  });

  it('should not resolve did after deletion', async () => {
    const domain = tlsDid.domain;

    //Delete DID
    await tlsDid.delete();

    //Resolve DID
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow();
  });
});
