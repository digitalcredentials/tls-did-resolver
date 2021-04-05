import { getResolver } from '../index';

const jsonRpcUrl = 'https://goerli.infura.io/v3/923dab15302f45aba7158692f117ac0c';
const domain = `tls-did.de`;

describe('TMP', () => {
  it('should resolve goerli did', async () => {
    console.log(`resolve did:tls:${domain}`);
    const tlsResolver = getResolver({ rpcUrl: jsonRpcUrl });
    try {
      const didDocument = await tlsResolver.tls(`did:tls:${domain}`, null, null);
      console.log(didDocument);
    } catch (error) {
      console.log(error.data);
    }
  });
});
