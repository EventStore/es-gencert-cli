# Event Store Certificate Generation CLI

The command line interface to ease the generation of a certificate authority and node certificates for Event Store Db 20.6.x and above.

## Getting Started

### Releases
The latest release for the ESGenCert CLI can be found under the [github releases page](https://github.com/EventStore/es-gencert-cli/releases).
We releases binaries for Windows/ Linux and MacOS.

### Usage

Basic usage for es-gencert-cli:
```
./es-gencert-cli [options] <command> [args]
```

Getting help for a specific command
```
./es-gencert-cli -help <command>
```
e.g.
```
./es-gencert-cli -help create-ca

Usage: create_ca [options]
  Generate a root/CA TLS certificate to be used with EventStoreDB
Options:
  -days                       The validity period of the certificate in days (default: 5 years)
  -out                        The output directory (default: ./ca)
```

### Examples
Generating a certificate authority
```
.\es-gencert-cli create-ca -out .\es-ca
```

Generating a certificate for an Event Store Db node
```
.\es-gencert-cli-cli.exe create-node -ca-certificate .\es-ca\ca.crt -ca-key .\es-ca\ca.key -out .\node1 -ip-addresses 127.0.0.1,172.20.240.1 -dns-names eventstore-node1.localhost.com
```

## Development

Building or working on `es-gencert-cli` requires a Go environment, version 1.14 or higher.