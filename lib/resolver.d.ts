export declare const REGISTRY = "0xf5513bc073A86394a0Fa26F11318D5D30AeAf550";
export declare function getResolver(provider: any, registryAddress?: string): {
    tls: (did: any) => Promise<object>;
};
