import HttpProvider from 'ethjs-provider-http';
import Eth from 'ethjs-query';
import EthContract from 'ethjs-contract';
import TLSDIDJson from 'tls-did-registry/build/contracts/TLSDID.json';
import TLSDIDRegistryJson from 'tls-did-registry/build/contracts/TLSDIDRegistry.json';
import filterAsync from 'node-filter-async';
import SSLCertificate from 'get-ssl-certificate';

//TODO import from tls-did-registry or tls-did-resolver
const REGISTRY = '0xc0b0F8f67C9605F99c9E774bBA66A0D9592aA0f5';

class Resolver {
  constructor(rpcUrl, registryAddress) {
    this.configureNetwork(rpcUrl);
    this.configureRegistry(REGISTRY || registryAddress);
  }

  configureProvider(rpcUrl) {
    //TODO extend to allow alternative providers
    return new HttpProvider(rpcUrl);
  }

  configureNetwork(rpcUrl) {
    const provider = this.configureProvider(rpcUrl);
    const eth = new Eth(provider);
    this.eth = eth;
  }

  configureRegistry(registryAddress) {
    const didRegistryContract = new EthContract(this.eth)(
      TLSDIDRegistryJson.abi
    );
    const didRegistry = didRegistryContract.at(registryAddress);
    this.registry = didRegistry;
  }

  async resolveDIDSC(did) {
    const addresses = (await this.registry.getContracts(did))['0'];

    const constracts = addresses.map((address) => {
      const tlsDidContract = new EthContract(this.eth)(TLSDIDJson.abi);
      return tlsDidContract.at(address);
    });

    const validConstracts = await filterAsync(
      constracts,
      async (constract) => await this.checkContractSignature(did, constract)
    );

    if (validConstracts.length == 1) {
      return validConstracts[0];
    } else {
      return undefined;
    }
  }

  async getPemFromServer(did) {
    const domain = did.substring(8);
    const certificate = await SSLCertificate.get(domain);
    return certificate.pemEncoded;
  }

  async checkContractSignature(did, contract) {
    const signature = (await contract.signature.call())['0'];

    const pem = this.getPemFromServer(did);

    //TODO: verification logic: valid signature on correct data
    // make sure data can not be replaced
    if (signature == 'test') {
      return true;
    } else {
      return false;
    }
  }

  resolveDID(did) {
    const didContract = this.resolveDIDSC(did);

    const publicKey = {};
  }
}

export default Resolver;
