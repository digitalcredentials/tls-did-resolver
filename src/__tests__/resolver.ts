import { getResolver } from '../index';

let resolver: { tls: (did: any) => Promise<object> };

describe('Resolver', () => {
  beforeAll(() => {
    resolver = getResolver();
  });
  it('should resolve did', async () => {
    const didDocument = await resolver.tls('did:tls:example.org');

    //TODO improve testing
    expect(didDocument).toBeTruthy();
  });
});
