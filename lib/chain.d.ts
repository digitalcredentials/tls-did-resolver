import { Contract, providers, Event } from 'ethers';
export declare function newRegistry(provider: providers.Provider, registryAddress: string): Promise<Contract>;
export declare function getClaimants(registry: Contract, domain: string): Promise<any[]>;
export declare function resolveClaimant(registry: Contract, domain: string, address: string): Promise<Event[]>;
