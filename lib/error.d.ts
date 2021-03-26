export declare class TLSDIDResolverError extends Error {
    data: {
        claimant: string;
        error: Error;
    }[];
    constructor(message: any, data: any);
    toString(): string;
}
