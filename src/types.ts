import { providers } from 'ethers';

export type ProviderConfig = {
  provider?: providers.Provider;
  rpcUrl?: string;
  web3?: any;
};

export type Attribute = {
  path: string;
  value: string;
};
