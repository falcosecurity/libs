# Falco Libs Dev Container

This dev container provides a complete development environment for building Falco libs.

## What's Included

- **Ubuntu 24.04** base image
- **Build tools**: gcc, g++, make, cmake (>= 3.24)
- **eBPF tools**: clang, llvm, bpftool
- **Development libraries**: libelf, libre2, libtbb, libjq, libjsoncpp, protobuf, gtest
- **Third-party dependencies**: Installed via `.github/install-deps.sh` (valijson, re2, uthash, BS_thread_pool)

## Usage

1. Open the project in VS Code
2. When prompted, click "Reopen in Container" or use the Command Palette:
   - Press `Cmd+Shift+P` (Mac) or `Ctrl+Shift+P` (Windows/Linux)
   - Select "Dev Containers: Reopen in Container"

## Building Falco Libs

Once inside the container, you can build the project:

```bash
# Configure with bundled dependencies (recommended for first build)
cmake -s . -b build -DUSE_BUNDLED_DEPS=ON

# Build libsinsp (includes libscap)
cmake --build build --target sinsp

# Or build specific targets:
# cmake --build build --target driver # Build kernel module
# cmake --build build --target scap   # Build libscap
```

## Building with Modern eBPF

To build with modern eBPF support:

```bash
cmake -s . -b build -DUSE_BUNDLED_DEPS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON
cmake --build build --target scap
```

## Running Tests

```bash
cmake -s . -b build -DUSE_BUNDLED_DEPS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON
cmake --build build --target run-unit-test-libsinsp
```

## Notes

- The container runs as a non-root user (`vscode`) but has sudo access
- Kernel module builds require kernel headers (included in the container)
- The `build/` directory is mounted from your host for faster rebuilds
- For driver testing, you may need to run with `sudo` privileges
