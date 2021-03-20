import { readFileSync } from 'fs';
import { getResolver } from '../index';
import { TLSDID } from '@digitalcredentials/tls-did';
import { Resolver, DIDResolver } from 'did-resolver';
import c from './testConfig.json';

let tlsResolver: { [index: string]: DIDResolver };
let tlsDid: TLSDID;

//Load certs and key
const cert = readFileSync(__dirname + c.certPath, 'utf8');
const intermediateCert = readFileSync(__dirname + c.intermediateCertPath, 'utf8');
const rootCert = readFileSync(__dirname + c.rootCertPath, 'utf8');
const pemKey = readFileSync(__dirname + c.privKeyPath, 'utf8');

const domain = `tls-did.de`;

describe('Resolver: Valid contracts', () => {
  beforeAll(async () => {
    //Instantiate resolver
    tlsResolver = getResolver({ rpcUrl: c.jsonRpcUrl }, c.registryAddress, [rootCert]);

    //Instantiate tlsDid
    tlsDid = new TLSDID(domain, c.etherPrivKey, {
      registry: c.registryAddress,
      providerConfig: {
        rpcUrl: c.jsonRpcUrl,
      },
    });

    //Register, update, sign TLS-DID
    await tlsDid.register();
    const chain = [cert, intermediateCert];
    await tlsDid.addChain(chain);
    await tlsDid.setExpiry(new Date('2100/12/12'));
    await tlsDid.addAttribute('parent/child1', 'value1');
    await tlsDid.addAttribute('parent/child2', 'value2');
    await tlsDid.sign(pemKey);
  });

  it('should resolve did', async () => {
    const didDocument = await tlsResolver.tls(`did:tls:${tlsDid.domain}`, null, null);

    expect(didDocument).toEqual({
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:tls:tls-did.de',
      parent: { child1: 'value1', child2: 'value2' },
      publicKey: [],
    });
  });

  it('should resolve did with universal resolver', async () => {
    const resolver = new Resolver({ ...tlsResolver });
    const didDocument = await resolver.resolve(`did:tls:${tlsDid.domain}`);

    expect(didDocument).toEqual({
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:tls:tls-did.de',
      parent: { child1: 'value1', child2: 'value2' },
      publicKey: [],
    });
  });

  it('should not resolve did after deletion', async () => {
    const domain = tlsDid.domain;

    //Delete DID
    await tlsDid.delete();

    //Resolve DID
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow(
      'did:tls:tls-did.de could not be validly resolved'
    );
  });

  afterAll(async () => {
    await tlsDid.delete();
    tlsDid = null;
  });
});

describe('Resolver: Invalid contracts', () => {
  beforeAll(async () => {
    //Instantiate tlsDid
    tlsDid = new TLSDID(domain, c.etherPrivKey, {
      registry: c.registryAddress,
      providerConfig: {
        rpcUrl: c.jsonRpcUrl,
      },
    });
  });

  it('should not resolve unregistered TLS-DID', async () => {
    //Resolve DID
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow(
      'did:tls:tls-did.de could not be validly resolved'
    );
  });

  it('should not resolve TLS-DID without signature', async () => {
    await tlsDid.register();

    //Resolve DID
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow(
      'did:tls:tls-did.de could not be validly resolved'
    );
  });

  it('should not resolve TLS-DID without chain', async () => {
    await tlsDid.sign(pemKey);

    //Resolve DID
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow(
      'did:tls:tls-did.de could not be validly resolved'
    );
  });

  it('should not resolve TLS-DID with expiry < today', async () => {
    //Add chain and expiry < today
    const chain = [cert, intermediateCert];
    await tlsDid.addChain(chain);
    await tlsDid.setExpiry(new Date('1999/12/12'));
    await tlsDid.sign(pemKey);

    //Resolve DID
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow(
      'did:tls:tls-did.de could not be validly resolved'
    );
  });

  afterAll(async () => {
    await tlsDid.delete();
    tlsDid = null;
  });
});
