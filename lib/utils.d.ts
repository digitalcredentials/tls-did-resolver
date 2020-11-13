import { JWKRSAKey } from 'jose';
import { Attribute, ServerCert } from './types';
export declare function verify(pemCert: string, signature: string, data: string): boolean;
export declare function hashContract(domain: string, address: string, attributes?: Attribute[], expiry?: Date): string;
export declare function getCertFromServer(did: string): Promise<ServerCert>;
export declare function debugCert(): string;
export declare function x509ToJwk(cert: string): JWKRSAKey;
export declare function addValueAtPath(object: object, path: string, value: any): void;
