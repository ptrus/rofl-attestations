# ROFL App Registry

A verification registry for ROFL (Runtime Off-chain Logic) applications running in Trusted Execution Environments on the Oasis Network.

## Quick Start

### Local Development

The registry depends on [rofl-app-backend](https://github.com/oasisprotocol/rofl-app-backend) for attestation verification.

```bash
# 1. Start rofl-app-backend (see its README for setup)
# Default: http://localhost:8899

# 2. Copy and edit configuration
cp config.yaml.example config.yaml
# Edit worker.backend_url if backend is not on localhost:8899

# 3. Build and run
make build
./rofl-registry --config config.yaml
```

Visit http://localhost:8000

## Configuration

All settings are in `config.yaml`. See `config.yaml.example` for details.
