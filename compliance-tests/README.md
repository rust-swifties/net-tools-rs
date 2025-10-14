# Compliance Tests

This directory contains compliance tests that verify net-tools-rs commands behave identically to the original net-tools implementation.

## Structure

- `tests/` - Individual test scripts for each command
- `Dockerfile` - Test environment with both implementations installed
- `run-tests.sh` - Runner script to execute all tests

## Running Tests

### Using Docker (recommended)

```bash
cd compliance-tests

# Build the test image (build context is parent directory)
docker build -f Dockerfile -t net-tools-compliance ..

# Run all tests
docker run --rm --privileged net-tools-compliance

# Run specific test
docker run --rm --privileged net-tools-compliance ./tests/nameif_test.sh
```

### Local testing (requires root)

```bash
cd ../
cargo build --release

# Run tests
sudo ./run-tests.sh
```

## Writing Tests

Each test script should:
1. Set up test environment (create dummy interfaces, config files, etc.)
2. Run the original command and capture output/behavior
3. Reset environment
4. Run the Rust implementation and capture output/behavior
5. Compare results
6. Clean up

Tests run in isolated network namespaces when possible to avoid interfering with the host system.

## CI Integration

These tests run in GitHub Actions using Docker containers with `--privileged` flag to allow network interface manipulation.
