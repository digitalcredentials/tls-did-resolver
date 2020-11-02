import { providers } from 'ethers';
import { getResolver } from '../index';

const jsonRpcUrl = 'http://127.0.0.1:8545';
let resolver: { tls: (did: any) => Promise<object> };

describe('Resolver', () => {
  beforeAll(() => {
    const provider = new providers.JsonRpcProvider(jsonRpcUrl);
    resolver = getResolver(provider);
  });

  it('should load did contracts', async () => {
    const didDocument = await resolver.tls('did:tls:example.org');

    //TODO improve testing
    expect(didDocument).toBeTruthy();
  });
});
