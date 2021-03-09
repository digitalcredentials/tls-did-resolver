import { readFileSync } from 'fs';
import tls from '../index';
import { TLSDID } from '@digitalcredentials/tls-did';
import { Resolver, DIDResolver } from 'did-resolver';
import c from './testConfig.json';

let tlsResolver: { [index: string]: DIDResolver };
let tlsDid: TLSDID;
let tlsDids: TLSDID[] = [];

//Load certs and key
const cert = readFileSync(__dirname + c.certPath, 'utf8');
const intermediateCert = readFileSync(__dirname + c.intermediateCertPath, 'utf8');
const rootCert = readFileSync(__dirname + c.rootCertPath, 'utf8');
const pemKey = readFileSync(__dirname + c.privKeyPath, 'utf8');

const domain = `tls-did.de`;

describe('Resolver: Valid contracts', () => {
  beforeAll(async () => {
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
    await tlsDid.setExpiry(new Date('2100/12/12'), pemKey);
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
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow('No contract was found');
  });

  afterAll(() => {
    tlsDid = null;
  });
});

describe('Resolver: Invalid contracts', () => {
  beforeAll(async () => {
    //Instantiate tlsDid
    tlsDid = new TLSDID(c.etherPrivKey, {
      registry: c.registryAddress,
      providerConfig: {
        rpcUrl: c.jsonRpcUrl,
      },
    });
  });

  it('should not resolve unregistered TLS-DID contract', async () => {
    await tlsDid.deployContract();

    //Resolve DID
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow('No contract was found');
  });

  it('should not resolve TLS-DID contract without chain', async () => {
    await tlsDid.registerContract(domain, pemKey);

    //Resolve DID
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow('1 contracts were found. None was valid.');
  });

  it('should not resolve TLS-DID contract with expiry < today', async () => {
    //Add chain and expiry < today
    const chain = [cert, intermediateCert];
    await tlsDid.addChain(chain, pemKey);
    await tlsDid.setExpiry(new Date('1999/12/12'), pemKey);

    //Resolve DID
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow('1 contracts were found. None was valid.');
  });

  afterAll(async () => {
    await tlsDid.delete();
    tlsDid = null;
  });
});
