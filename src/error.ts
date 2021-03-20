export class TLSDIDResolverError extends Error {
  data: { claimant: string; error: Error }[];
  constructor(message, data) {
    super(message);
    this.name = 'TLSDIDResolverError';
    this.data = data;
  }

  toString() {
    return `${this.message} ${this.data.toString()}`;
  }
}
