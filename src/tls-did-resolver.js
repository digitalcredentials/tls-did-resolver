import HttpProvider from 'ethjs-provider-http';
import Eth from 'ethjs-query';
import EthContract from 'ethjs-contract';
import TLSDIDContract from '../contracts/tls-did-contract.json';
import TLSDIDRegsitryContract from '../contracts/tls-did-registry-contract.json';
import filterAsync from 'node-filter-async';
import SSLCertificate from 'get-ssl-certificate';

class Resolver {
  constructor(rpcUrl, registryAddress) {
    this.eth = this.configureNetwork(rpcUrl);
    this.registry = this.configureRegistry(registryAddress);
  }

  configureProvider(rpcUrl) {
    //TODO extend to allow alternative providers
    return new HttpProvider(rpcUrl);
  }

  configureNetwork(rpcUrl) {
    const provider = this.configureProvider(rpcUrl);
    const eth = new Eth(provider);
    return eth;
  }

  configureRegistry(registryAddress) {
    const didRegistryContract = new EthContract(this.eth)(
      TLSDIDRegsitryContract
    );
    const didRegistry = didRegistryContract.at(registryAddress);
    return didRegistry;
  }

  async resolveDIDSC(did) {
    const addresses = (await this.registry.getTSLDIDContracts(did))['0'];

    const constracts = addresses.map((address) => {
      const tlsDidContract = new EthContract(this.eth)(TLSDIDContract);
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
