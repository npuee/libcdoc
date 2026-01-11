# libcdoc

This repository is a fork of the original open-eid/libcdoc, modified specifically to interoperate with the
`npuee/npu-cdoc-encrypt` client/tooling: https://github.com/npuee/npu-cdoc-encrypt

A encryption library for CDoc container format.

## Features

- CDoc1 encryption by certificate (RSA/ECC)
- CDoc1 decryption (PKSC11/NCrypt private key)
- CDoc2 encryption by public key (RSA/ECC)
- CDoc2 decryption by private key (PKSC11/NCrypt)
- CDoc2 key-server support
- CDoc2 symmetric encryption (AES)
- CDoc2 symmetric encryption (password-based)

For more information refer [doc/intro.md](doc/intro.md) document.

**This fork — notable changes**

- This fork is simplified to an encrypt-first workflow to work cleanly with the `npu-cdoc-encrypt` tooling.
- The CLI accepts input via `--in <file>` or as a positional input file.
- Recipient format is restricted to certificate files using the syntax: `label:cert:PATH` (PATH is an absolute or relative path to a DER/PEM certificate file).
- Default behavior: produce CDOC1 (`-v1`) and automatically generate the lock label (`--genlabel`) unless explicitly overridden.
- The tool is silent by default; pass `--verbose` to enable console output for diagnostics.
- The top-level subcommand defaults to `encrypt` when omitted, i.e. calling the binary without a subcommand runs encryption.

These changes were introduced to make the command-line behavior predictable for use with `npuee/npu-cdoc-encrypt`.

See the "Usage example" below for a basic interoperability example.

## Building
[![Build Status](https://github.com/open-eid/libcdoc/workflows/CI/badge.svg?branch=master)](https://github.com/open-eid/libcdoc/actions)

### Ubuntu, Fedora

1. Install dependencies

        # Ubuntu
        sudo apt install cmake libxml2-dev zlib1g-dev
        # Fedora
        sudo dnf install cmake gcc-c++ libtool-ltdl-devel libxml2-devel openssl-devel zlib-devel

	* flatbuffers - required
	* doxygen - Optional, for API documentation
	* libboost-test-dev - Optional, for unit tests
	* swig - Optional, for C# and Java bindings
	* openjdk-17-jdk-headless - Optional, for Java bindings

2. Fetch the source

		git clone https://github.com/open-eid/libcdoc.git
		cd libcdoc

3. Configure

		cmake -B build -S .

4. Build

		cmake --build build

5. Install

		sudo cmake --build build --target install

	Usage example (Windows PowerShell)

	    # build with vcpkg support
	    .\build.ps1 -UseVcpkg

	    # encrypt a file (defaults: CDOC1, generated label)
	    .\build\Debug\cdoc-tool.exe encrypt --in C:\path\to\file.txt --rcpt label:cert:C:\path\to\recipient.der --out C:\path\to\out.cdoc

	    # enable verbose output
	    .\build\Debug\cdoc-tool.exe --verbose encrypt --in C:\path\to\file.txt --rcpt label:cert:C:\path\to\recipient.der --out C:\path\to\out.cdoc

	Notes

	- The `--rcpt` option only accepts `label:cert:PATH` recipient entries in this fork. The PATH must point to the recipient certificate file (DER or PEM).
	- The produced `.cdoc` files are intended to be consumed by tools compatible with the CDOC1 format, including `npuee/npu-cdoc-encrypt` workflows.
	- If you need the original multi-mode behavior (decrypt/re-encrypt/locks), refer to the upstream repository: https://github.com/open-eid/libcdoc

### macOS

1. Install dependencies from
	* [XCode](https://developer.apple.com/xcode/) - For macOS/iOS development
	* [CMake](https://cmake.org)
	* [Homebrew](https://brew.sh)

2. Fetch the source

        git clone https://github.com/open-eid/libcdoc.git
        cd libdcdoc

3. Install dependencies

        brew install flatbuffers openssl opensc

 	* flatbuffers - Required
	* openssl - Required, version 3.0.0 or later
	* opensc - Optional, for smart-card operations
	* doxygen - Optional, for API documentation
	* boost - Optional, for unit tests
	* swig - Optional, for C# and Java bindings
	* openjdk - Optional, for Java bindings

4. Configure

        cmake -B build -S .

5. Build

        cmake --build build

6. Install

        sudo cmake --build build --target install

### Windows

1. Install dependencies and necessary tools from
	* [Visual Studio Community 2022](https://www.visualstudio.com/downloads/)
	* [CMake](http://www.cmake.org)
	* [vcpkg](https://vcpkg.io/)
	* [Swig](http://swig.org/download.html) - Optional, for C#, Python and Java bindings
	* [Doxygen](https://www.doxygen.nl/download.html) - Optional, for generating documentation
	* [Wix toolset](http://wixtoolset.org/releases/) - Optional, for creating Windows installation packages
	* [Python](https://www.python.org/downloads/) - Optional, for Python bindings
	* [Java](https://www.oracle.com/java/technologies/downloads/) - Optional, for Java bindings

2. Open desired Visual Studio tools command prompt:
	* x64 Native Tool Command Prompt
	* x86 Native Tool Command Prompt
	* ARM64 Native Tool Command Prompt
	* Or some cross compile combination with target host type

3. Fetch the source

        git clone https://github.com/open-eid/libcdoc.git
        cd libcdoc

4. Configure and Build

        .\build.ps1
