import Resolver from '../tls-did-resolver';

const rpcEndpoint = 'http://127.0.0.1:8545';

describe('Resolver', () => {
  const resolver = new Resolver(rpcEndpoint);

  it('throws when no configuration is provided', async () => {
    const contracts = await resolver.resolveDIDSC('did:tls:example.org');

    console.log(contracts);
    //  assert.deepEqual(
    //    address,
    //    [address, '0xdC2c16ccC8291c43B83D24E37900A3bed3EEd408'],
    //    'Identical did => address mapping was added'
    //  );
  });
});
