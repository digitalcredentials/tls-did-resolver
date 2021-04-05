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

  it('should resolve did after attribute update', async () => {
    //Connect to exiting claim and update information
    const tlsDidDuplicate = new TLSDID(domain, c.etherPrivKey, {
      registry: c.registryAddress,
      providerConfig: {
        rpcUrl: c.jsonRpcUrl,
      },
    });

    await tlsDidDuplicate.loadDataFromRegistry();
    await tlsDidDuplicate.addAttribute('parent/child3', 'value3');
    await tlsDidDuplicate.sign(pemKey);

    const resolver = new Resolver({ ...tlsResolver });
    const didDocument = await resolver.resolve(`did:tls:${tlsDid.domain}`);

    expect(didDocument).toEqual({
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:tls:tls-did.de',
      parent: { child1: 'value1', child2: 'value2', child3: 'value3' },
      publicKey: [],
    });
  });

  it('should resolve did after large update', async () => {
    //Connect to exiting claim and update information
    const tlsDidDuplicate = new TLSDID(domain, c.etherPrivKey, {
      registry: c.registryAddress,
      providerConfig: {
        rpcUrl: c.jsonRpcUrl,
      },
    });
    await tlsDidDuplicate.loadDataFromRegistry();

    await tlsDidDuplicate.addChain([cert, intermediateCert]);

    await tlsDidDuplicate.addAttribute('parent/child', 'value', 50000);
    await tlsDidDuplicate.addAttribute('arrayA[0]/element', 'value', 50000);
    await tlsDidDuplicate.addAttribute('arrayB[0]', 'value', 50000);
    await tlsDidDuplicate.addAttribute('assertionMethod[0]/id', `did:tls:${domain}#keys-2`, 50000);
    await tlsDidDuplicate.addAttribute('assertionMethod[0]/type', 'Ed25519VerificationKey2018', 50000);
    await tlsDidDuplicate.addAttribute('assertionMethod[0]/controller', `did:tls:${domain}`, 50000);
    await tlsDidDuplicate.addAttribute(
      'assertionMethod[0]/publicKeyBase58',
      'H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV',
      50000
    );
    await tlsDidDuplicate.setExpiry(new Date('2040/12/12'), 50000);
    await tlsDidDuplicate.sign(pemKey, 50000);

    //Resolve DID
    const didDocument = await tlsResolver.tls(`did:tls:${tlsDidDuplicate.domain}`, null, null);
    expect(didDocument).toEqual({
      '@context': 'https://www.w3.org/ns/did/v1',
      arrayA: [{ element: 'value' }],
      arrayB: ['value'],
      assertionMethod: [
        {
          controller: 'did:tls:tls-did.de',
          id: 'did:tls:tls-did.de#keys-2',
          publicKeyBase58: 'H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV',
          type: 'Ed25519VerificationKey2018',
        },
      ],
      id: 'did:tls:tls-did.de',
      parent: { child: 'value', child1: 'value1', child2: 'value2', child3: 'value3' },
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

const privateKeys = [
  '0xc5aea55f87a4ac6dd2d030012d0c46a76e4c64e9bcea7194b3abd72cc4d4d73a',
  '0x547bb9d0a10c7ed1988f6180f6e191e999b9e6e16314fa69271a667b99cdca1b',
  '0x70b096141e49191a1986d30e4bb4e8dff29b3994bd1d804cda0ab2979ccda258',
  '0xfcd5fea1c4201a8ca91366f49c8c5c61524c969cb1b0d6dc6d62e538439b4764',
  '0xdc9d97047a48bba07a5671841fd0e1143a8c56b914452f9834a4775b58c93293',
  '0x0109dd86311b88812d8d740ed776fe02ab05a26ebdcfb52b1b6989b1d5c9636c',
  '0xe57d62a92a26b405d6349cca5c8855d0043295d755546c1a003a5a9d9e97cff1',
  '0x5b68951482c4d815d6e04bda1f23aa24411e2db5206efeeaa80d4805fc5361e9',
];

describe('Resolver: Multiple contracts', () => {
  let tlsDids = [];
  beforeAll(async () => {
    //Instantiate resolver
    tlsResolver = getResolver({ rpcUrl: c.jsonRpcUrl }, c.registryAddress, [rootCert]);
  });

  it('should not resolve if all TLS-DID claim are invalid', async () => {
    tlsDids.push(await createTLSDID(privateKeys[0], false));
    tlsDids.push(await createTLSDID(privateKeys[1], false));
    //Resolve DID

    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow(
      'did:tls:tls-did.de could not be validly resolved'
    );
  });

  it('should resolve if single TLS-DID claim is valid', async () => {
    tlsDids.push(await createTLSDID(c.etherPrivKey, true));

    //Resolve DID
    let didDocument;
    try {
      didDocument = await tlsResolver.tls(`did:tls:${domain}`, null, null);
    } catch (error) {
      console.log(error.data);
    }

    expect(didDocument).toEqual({
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:tls:tls-did.de',
      parent: { child1: 'value1', child2: 'value2' },
      publicKey: [],
    });
  });

  it('should not resolve if multiple TLS-DID claim are valid', async () => {
    tlsDids.push(await createTLSDID(privateKeys[4], true));

    //Resolve DID
    await expect(tlsResolver.tls(`did:tls:${domain}`, null, null)).rejects.toThrow(
      'did:tls:tls-did.de could not be unambiguously resolved. 4 claimants exist, at least two have a valid claim.'
    );
  });

  afterAll(async () => {
    //Delete TLS-DID
    for (let i = 0; i < tlsDids.length; i++) {
      await tlsDids[i].delete();
    }
  });
});

async function createTLSDID(etherPrivKey: string, signed: boolean) {
  let tlsDid = new TLSDID(domain, etherPrivKey, {
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
  if (signed) {
    await tlsDid.sign(pemKey);
  }
  return tlsDid;
}
