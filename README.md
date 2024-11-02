Key block library and tools for ANSI X9.143, ASC X9 TR-31 and ISO 20038
=======================================================================

[![License: LGPL-2.1](https://img.shields.io/github/license/openemv/tr31)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)<br/>
[![Ubuntu build](https://github.com/openemv/tr31/actions/workflows/ubuntu-build.yaml/badge.svg)](https://github.com/openemv/tr31/actions/workflows/ubuntu-build.yaml)<br/>
[![Fedora build](https://github.com/openemv/tr31/actions/workflows/fedora-build.yaml/badge.svg)](https://github.com/openemv/tr31/actions/workflows/fedora-build.yaml)<br/>
[![MacOS build](https://github.com/openemv/tr31/actions/workflows/macos-build.yaml/badge.svg)](https://github.com/openemv/tr31/actions/workflows/macos-build.yaml)<br/>
[![Windows build](https://github.com/openemv/tr31/actions/workflows/windows-build.yaml/badge.svg)](https://github.com/openemv/tr31/actions/workflows/windows-build.yaml)<br/>

This project began as an implementation of the ASC X9 TR-31 standard and has
since grown to include the ANSI X9.143 standard which supersedes it, and the
ISO 20038 standard which extends it. However, this project continues to refer
to the library as TR-31 and prefixes the API, data types and command line tool
with `tr31`, while mostly avoiding that naming when refering to key blocks and
data associated with key blocks. Given that most uses of these standards
involve dedicated security hardware, this implementation is mostly for
validation and debugging purposes.

If you wish to use this library for a project that is not compatible with the
terms of the LGPL v2.1 license, please contact the author for alternative
licensing options.

Features
--------

Currently this project implements parsing/decryption and encoding/encryption
of key block format versions A, B, C, D and E. Various helper functions are
also available to stringify key block header attributes. The functionality is
available as a library as well as a command line tool.

Installation
------------

* For Ubuntu 20.04 LTS (Focal), 22.04 LTS (Jammy), or 24.04 LTS (Noble) install
  the appropriate [release package](https://github.com/openemv/tr31/releases)
* For Fedora 40 or Fedora 41, install the appropriate
  [release package](https://github.com/openemv/tr31/releases)
* For Gentoo, use the
  [OpenEMV overlay](https://github.com/openemv/openemv-overlay), set the
  keywords and useflags as needed, and install using
  `emerge --verbose --ask tr31`
* For MacOS with [Homebrew](https://brew.sh/), use the
  [OpenEMV tap](https://github.com/openemv/homebrew-tap) and install using
  `brew install openemv/tap/tr31`
* For Windows, use [MSYS2](https://www.msys2.org/) and follow the build
  instructions below
* For other platforms, architectures or configurations, follow the build
  instructions below

Dependencies
------------

* C11 compiler such as GCC or Clang
* [CMake](https://cmake.org/)
* TR-31 library requires [MbedTLS](https://github.com/Mbed-TLS/mbedtls)
  (preferred), or [OpenSSL](https://www.openssl.org/)
* `tr31-tool` will be built by default and requires `argp` (either via Glibc, a
  system-provided standalone or a downloaded implementation; see
  [MacOS / Windows](#macos--windows)). Use the `BUILD_TR31_TOOL` option to
  prevent TR-31 tool from being built and avoid the dependency on `argp`.
* [Doxygen](https://github.com/doxygen/doxygen) can _optionally_ be used to
  generate API documentation if it is available; see
  [Documentation](#documentation)
* [bash-completion](https://github.com/scop/bash-completion) can _optionally_
  be used to generate bash completion for `tr31-tool`

This project also makes use of sub-projects that can either be provided as
git submodules using `git clone --recurse-submodules`, or provided as CMake
targets by a parent project:
* [OpenEMV common crypto abstraction](https://github.com/openemv/crypto)

Build
-----

This project uses CMake and can be built using the usual CMake steps.

To generate the build system in the `build` directory, use:
```shell
cmake -B build
```

To build the project, use:
```shell
cmake --build build
```

Consult the CMake documentation regarding additional options that can be
specified in the above steps.

Testing
-------

The tests can be run using the `test` target of the generated build system.

To run the tests using CMake, do:
```shell
cmake --build build --target test
```

Alternatively, [ctest](https://cmake.org/cmake/help/latest/manual/ctest.1.html)
can be used directly which also allows actions such as `MemCheck` to be
performed or the number of jobs to be set, for example:
```shell
ctest --test-dir build -T MemCheck -j 10
```

Documentation
-------------

If Doxygen was found by CMake, then HTML documentation can be generated using
the `docs` target of the generated build system.

To generate the documentation using CMake, do:
```shell
cmake --build build --target docs
```

Alternatively, the `BUILD_DOCS` option can be specified when generating the
build system by adding `-DBUILD_DOCS=YES`.

Packaging
---------

If the required packaging tools were found (`dpkg` and/or `rpmbuild` on Linux)
by CMake, packages can be created using the `package` target of the generated
build system.

To generate the packages using CMake, do:
```shell
cmake --build build --target package
```

Alternatively, [cpack](https://cmake.org/cmake/help/latest/manual/cpack.1.html)
can be used directly from within the build directory (`build` in the above
[Build](#build) steps).

This is an example of how monolithic release packages can be built from
scratch on Ubuntu or Fedora:
```shell
rm -Rf build &&
cmake -B build -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=YES -DBUILD_DOCS=YES -DCPACK_COMPONENTS_GROUPING=ALL_COMPONENTS_IN_ONE &&
cmake --build build &&
cmake --build build --target package
```

MacOS / Windows
---------------

On platforms such as MacOS or Windows where static linking is desirable and
dependencies such as MbedTLS or `argp` may be unavailable, the `FETCH_MBEDTLS`
and `FETCH_ARGP` options can be specified when generating the build system.

In addition, MacOS universal binaries can be built by specifying the desired
architectures using the `CMAKE_OSX_ARCHITECTURES` option.

This is an example of how a self-contained, static, universal binary can be
built from scratch for MacOS:
```shell
rm -Rf build &&
cmake -B build -DCMAKE_OSX_ARCHITECTURES="x86_64;arm64" -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DFETCH_MBEDTLS=YES -DFETCH_ARGP=YES &&
cmake --build build
```

Usage
-----

The available command line options of the `tr31-tool` application can be
displayed using:
```shell
tr31-tool --help
```

To decode a key block, use the `--import` option. For example:
```shell
tr31-tool --import B0128B1TX00N0300KS18FFFF00A0200001E00000KC0C000169E3KP0C00ECAD626F9F1A826814AA066D86C8C18BD0E14033E1EBEC75BEDF586E6E325F3AA8C0E5
```

To decrypt a key block, add the `--kbpk` option to specify the key block
protection key to be used for decryption. For example:
```shell
tr31-tool --import B0128B1TX00N0300KS18FFFF00A0200001E00000KC0C000169E3KP0C00ECAD626F9F1A826814AA066D86C8C18BD0E14033E1EBEC75BEDF586E6E325F3AA8C0E5 --kbpk AB2E09DB3EF0BA71E0CE6CD755C23A3B
```

To encode/encrypt a key block, use the `--export` option to specify the key to
be wrapped/encrypted. The key block attributes can be specified using either a
combination of the `--export-format-version B`, `--export-key-algorithm` and
`--export-template` options, or using the `--export-header` option. For
example:
```shell
tr31-tool --kbpk AB2E09DB3EF0BA71E0CE6CD755C23A3B --export BF82DAC6A33DF92CE66E15B70E5DCEB6 --export-header B0000B1TX00N0200KS18FFFF00A0200001E00000KC0C000169E3
```

Individual optional blocks can also be added when exporting a key block by
using the various `--export-opt-block-XX` functions, where `XX` is the optional
block identifier. For example:
```shell
tr31-tool --kbpk AB2E09DB3EF0BA71E0CE6CD755C23A3B --export BF82DAC6A33DF92CE66E15B70E5DCEB6 --export-header B0000B1TX00N0000 --export-opt-block-KS FFFF00A0200001E00000 --export-opt-block-KC
```

To decode non-standard key blocks, use the `--import-no-strict-validation`
option to disable strict validation during key block import. For example:
```shell
tr31-tool --import D014410A100N0200101CIBMC01140123456789ABCDEFPB04012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345 --import-no-strict-validation
```

Roadmap
-------

* Implement key block translation
* Implement key block component combination
* Add support for vcpkg
* Test on various ARM architectures

License
-------

Copyright 2020-2024 [Leon Lynch](https://github.com/leonlynch).

This project is licensed under the terms of the LGPL v2.1 license. See
[LICENSE](https://github.com/openemv/tr31/blob/master/LICENSE) file.
