# Event Store Certificate Generation CLI

The command line interface to ease the generation of a certificate authority and node certificates for EventStoreDB 20.6.x and above.

## Getting Started

### Releases

The latest release for the es-gencert-cli can be found under the [GitHub releases page](https://github.com/EventStore/es-gencert-cli/releases).
We releases binaries for Windows, Linux and macOS. We also publish the tool as a Docker image.

### Usage

Basic usage for es-gencert-cli:

```
./es-gencert-cli [options] <command> [args]
```

Getting help for a specific command:

```bash
./es-gencert-cli -help <command>
```

e.g.

```bash
./es-gencert-cli -help create-ca

Usage: create_ca [options]
  Generate a root/CA TLS certificate to be used with EventStoreDB
Options:
  -days                       The validity period of the certificate in days (default: 5 years)
  -out                        The output directory (default: ./ca)
```

## Running with Docker

You could also run the tool using Docker interactive container:

```bash
docker run --rm -i eventstore/es-gencert-cli <command> <options>
```

One useful scenario is to use the tool inside the Docker Compose file to generate all the necessary certificates before starting cluster nodes. You can find an [example](https://github.com/EventStore/EventStore/blob/master/docker-compose.yml) in the EventStoreDB repository.

### Examples

Generating a certificate authority:

```bash
./es-gencert-cli create-ca -out ./es-ca
```

Generating a certificate for an EventStoreDB node:

```
./es-gencert-cli create-node -ca-certificate ./es-ca/ca.crt -ca-key ./es-ca/ca.key -out ./node1 -ip-addresses 127.0.0.1,172.20.240.1 -dns-names localhost,eventstore-node1.localhost.com
```

Generating certificates using config file:

```
./es-gencert-cli create-certs --config-file ./certs.yml
```

An example config file:

```yaml
certificates:
  ca-certs:
    - out: './root_ca'
    - out: './intermediate_ca'
      cert-path: './root_ca/ca.crt'
      key-path: './root_ca/ca.key'
      days: 5
  node-certs:
    - out: './node1'
      ca-certificate: './intermediate_ca/ca.crt'
      ca-key: './intermediate_ca/ca.key'
      ip-addresses: '127.0.0.1,172.20.240.1'
      dns-names: 'localhost,eventstore-node1.localhost.com'
    - out: './node2'
      ca-certificate: './intermediate_ca/ca.crt'
      ca-key: './intermediate_ca/ca.key'
      ip-addresses: '127.0.0.2,172.20.240.2'
      dns-names: 'localhost,eventstore-node2.localhost.com'
    - out: './node3'
      ca-certificate: './intermediate_ca/ca.crt'
      ca-key: './intermediate_ca/ca.key'
      ip-addresses: '127.0.0.3,172.20.240.3'
      dns-names: 'localhost,eventstore-node2.localhost.com'
```

## Development

Building or working on `es-gencert-cli` requires a Go environment, version 1.14 or higher.

### Code Quality and Linting

Before pushing your changes, please ensure that your code adheres to the project's coding standards and guidelines. To facilitate this, we use `golangci-lint` for static code analysis. Running `golangci-lint` helps catch issues early and improves the overall quality of the codebase.

#### Running golangci-lint

To run `golangci-lint` on your local development machine, follow these steps:

1. If you haven't already, install `golangci-lint` on your machine. You can find the installation instructions on the [golangci-lint GitHub page](https://github.com/golangci/golangci-lint).

2. Navigate to the root directory of your local `es-gencert-cli` repository.

3. Run the linting process with the following command:

   ```bash
   golangci-lint run
   ```

4. Carefully review any linting warnings or errors it may report. Resolve all issues before committing your changes.

This process helps maintain a high standard for the code and eases code reviews and integration.

Please ensure that you have set up your development environment as per the instructions in the [Getting Started](#getting-started) section, and have the correct version of Go installed.
