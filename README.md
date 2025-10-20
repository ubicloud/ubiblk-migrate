# UBI Block Migration Tool

This project contains tools for working with Ubi block devices, for converting SPDK base image with its overlay into a new disk with its own format.

## Components

### migrate
This utility reads an overlay image file and extracts metadata information, including:
- Verification of magic bytes
- Version information
- Stripe size
- Stripe header values (1 = present, 0 = not present)

## Building and Running

First you need to install the prerequisites:
```bash
sudo apt update
sudo apt install -y make autoconf gcc clang libtool
```

To build, run:
```bash
make
```

To clean the build, run:
```bash
make clean
```

## Command Line Arguments

### migrate
```bash
./migrate -base-image=<path> -overlay-image=<path> -output-image=<path>
```

## Metadata Format

The metadata follows the format defined in the UBI specification:
- The first 8MB of the overlay image contains the metadata
- The metadata contains an array of stripe headers, each indicating whether a stripe is present (1) or not present (0)
