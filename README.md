
# Usage & Documentation

```
npm i @digitalcredentials/tls-did-resolver
```

The documentation for the TLS-DID Method and it's libraries can be found in the [tls-did repository](https://github.com/digitalcredentials/tls-did/blob/master/README.md).

# Development

## Installation

```
npm i
```
## Test

Clone tls-did-playground to same root folder

```
cd ../tls-did-playground
npm run testnet
npm run deployRegistry
```

Verify that the etherPrivKey and registryAddress in ```tls-did-resolver/src/__test__/testConfig.json``` are identical to ```tls-did-playground/environment.json```.

```
cd ../tls-did-resolver
npm run test
```
## Build

Should be run before each commit.

```
npm run build
```

## Release

```
npm run build
```

Commit changes

```
npm run release
```
