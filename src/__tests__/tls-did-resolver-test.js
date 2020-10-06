import Resolver from '../tls-did-resolver';

const rpcEndpoint = 'http://127.0.0.1:8545';
const registryAddress = '0xFB23a2B2de2761Baf158bbff67Fd564E611bb50d';

describe('Resolver', () => {
  const resolver = new Resolver(rpcEndpoint, registryAddress);

  it('throws when no configuration is provided', async () => {
    const contracts = await resolver.resolveDIDSC('did:tls:example.com');

    console.log(contracts);
    //  assert.deepEqual(
    //    address,
    //    [address, '0xdC2c16ccC8291c43B83D24E37900A3bed3EEd408'],
    //    'Identical did => address mapping was added'
    //  );
  });
});
