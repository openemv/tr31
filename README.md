TR-31 library and tools
=======================

[![License: LGPL-2.1](https://img.shields.io/github/license/openemv/tr31)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)<br/>
[![Ubuntu build](https://github.com/openemv/tr31/actions/workflows/ubuntu-build.yaml/badge.svg)](https://github.com/openemv/tr31/actions/workflows/ubuntu-build.yaml)<br/>
[![MacOS build](https://github.com/openemv/tr31/actions/workflows/macos-build.yaml/badge.svg)](https://github.com/openemv/tr31/actions/workflows/macos-build.yaml)<br/>
[![Windows build](https://github.com/openemv/tr31/actions/workflows/windows-build.yaml/badge.svg)](https://github.com/openemv/tr31/actions/workflows/windows-build.yaml)<br/>

This library is an implementation of the ASC X9 TR-31 standard. Given that
most uses of this standard involve dedicated security hardware, this
implementation is mostly for validation and debugging purposes.

Features
--------

Currently this library implements parsing/decryption and encoding/encryption
of TR-31 format version A, B, C, and D. Various helper functions are also
available to stringify TR-31 header attributes.

Dependencies
------------

* C11 compiler such as GCC or Clang
* CMake
* TR-31 library requires MbedTLS (preferred), or OpenSSL
* TR-31 tool requires argp (either via Glibc or a standalone implementation)

This project also makes use of the OpenEMV common crypto abstraction
(https://github.com/openemv/crypto), which in turn depends on a cryptographic
implementation such as MbedTLS (preferred) or OpenSSL. This abstraction should
either be provided as a git submodule in the `crypto` subdirectory using
`git clone --recurse-submodules`, or its CMake targets should be provided by a
parent project.

Build
-----

This project uses CMake and can be built using the usual CMake steps.

To generate the build system in the `build` directory, use:
```
cmake -B build
```

To build the project, use:
```
cmake --build build
```

Consult the CMake documentation regarding additional options that can be
specified in the above steps.

Testing
-------

The tests can be run using the `test` target of the generated build system.

To run the tests using CMake, do:
```
cmake --build build --target test
```

If the CMake generator was `Unix Makefiles` (default on Linux), the tests can
can be run from within the build directory (`build` in the above
[Build](#build) steps) using:
```
make test
```

Documentation
-------------

If Doxygen was found by CMake, then HTML documentation can be generated using
the `docs` target of the generated build system.

To generate the documentation using CMake, do:
```
cmake --build build --target docs
```

If the CMake generator was `Unix Makefiles` (default on Linux), the
documentation can be generated from within the build directory (`build` in
the above [Build](#build) steps) using:
```
make docs
```

Alternatively, the `BUILD_DOCS` option can be specified when generating the
build system by adding `-DBUILD_DOCS=ON`.

Packaging
---------

If the required packaging tools were found (`dpkg` and/or `rpmbuild` on Linux)
by CMake, packages can be created using the `package` target of the generated
build system.

To generate the packages using CMake, do:
```
cmake --build build --target package
```

If the CMake generator was `Unix Makefiles` (default on Linux), the packages
can be generated from within the build directory (`build` in the above
[Build](#build) steps) using:
```
make package
```

This is an example of how monolithic release packages can be built from
scratch on Ubuntu or Fedora:
```
rm -Rf build &&
cmake -B build -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=YES -DBUILD_DOCS=YES -DCPACK_COMPONENTS_GROUPING=ALL_COMPONENTS_IN_ONE &&
cmake --build build &&
cmake --build build --target package
```

MacOS / Windows
---------------

On platforms such as MacOS or Windows where static linking is desirable and
dependencies such as MbedTLS or argp may be unavailable, the `FETCH_MBEDTLS`
and `FETCH_ARGP` options can be specified when generating the build system.

In addition, MacOS universal binaries can be built by specifying the desired
architectures using the `CMAKE_OSX_ARCHITECTURES` option.

This is an example of how a self-contained, static, universal binary can be
built from scratch for MacOS:
```
rm -Rf build &&
cmake -B build -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DCMAKE_OSX_ARCHITECTURES="x86_64;arm64" -DFETCH_MBEDTLS=YES -DFETCH_ARGP=YES &&
cmake --build build
```

Usage
-----

The available command line options of the `tr31-tool` application can be
displayed using:
```
tr31-tool --help
```

To decode a TR-31 key block, use the `--import` option. For example:
```
tr31-tool --import B0128B1TX00N0300KS18FFFF00A0200001E00000KC0C000169E3KP0C00ECAD626F9F1A826814AA066D86C8C18BD0E14033E1EBEC75BEDF586E6E325F3AA8C0E5
```

To decrypt a TR-31 key block, add the `--kbpk` option to specify the key block
protection key to be used for decryption. For example:
```
tr31-tool --import B0128B1TX00N0300KS18FFFF00A0200001E00000KC0C000169E3KP0C00ECAD626F9F1A826814AA066D86C8C18BD0E14033E1EBEC75BEDF586E6E325F3AA8C0E5 --kbpk AB2E09DB3EF0BA71E0CE6CD755C23A3B
```

To encode/encrypt a TR-31 key block, use the `--export` option to specify the
key to be wrapped/encrypted. The key block attributes can be specified using
either a combination of the `--export-format-version B`,
`--export-key-algorithm` and `--export-template` options, or using the
`--export-header` option. For example:
```
tr31-tool --kbpk AB2E09DB3EF0BA71E0CE6CD755C23A3B --export BF82DAC6A33DF92CE66E15B70E5DCEB6 --export-header B0128B1TX00N0300KS18FFFF00A0200001E00000KC0C000169E3KP0C00ECAD62
```

Roadmap
-------

* Implement authoring of key blocks for HMAC keys using TR-31 tool
* Implement key block translation
* Implement key block component combination
* Add CPack packaging for Windows and MacOS
* Test on various ARM architectures

License
-------

Copyright (c) 2020, 2021, 2022 Leon Lynch.

This project is licensed under the terms of the LGPL v2.1 license. See LICENSE file.
