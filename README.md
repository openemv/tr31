TR-31 library and tools
=======================

This library is an implementation of the ASC X9 TR-31 standard. Given that
most uses of this standard involve dedicated security hardware, this
implementation is mostly for validation and debugging purposes.

Features
========

Currently this library implements parsing and decryption of TR-31 format
version A, B, C, and D. Various helper functions are also available to
stringify TR-31 header attributes.

Build
=====

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
=======

Assuming the default CMake generator was `Unix Makefiles` (default on Linux),
tests can be run from within the build directory (`build` in the above
[Build](#build) steps) using:
```
make test
```

Packaging
=========

Assuming the default CMake generator was `Unix Makefiles` (default on Linux),
and the required packaging tools were found (`dpkg` and/or `rpmbuild` on
Linux), then packages can be built from within the build directory (`build` in
the above [Build](#build) steps) using:
```
make package
```

Usage:
======

The available command line options of the `tr31-tool` application can be
displayed using:
```
tr31-tool --help
```

To decode a TR-31 key block, use the `--key-block` option. For example:
```
tr31-tool --key-block B0128B1TX00N0300KS18FFFF00A0200001E00000KC0C000169E3KP0C00ECAD626F9F1A826814AA066D86C8C18BD0E14033E1EBEC75BEDF586E6E325F3AA8C0E5
```

To decrypt a TR-31 key block, add the `--kbpk` option to specify the key block
protection key to be used for decryption. For example:
```
tr31-tool --key-block B0128B1TX00N0300KS18FFFF00A0200001E00000KC0C000169E3KP0C00ECAD626F9F1A826814AA066D86C8C18BD0E14033E1EBEC75BEDF586E6E325F3AA8C0E5 --kbpk AB2E09DB3EF0BA71E0CE6CD755C23A3B
```

Roadmap
=======

* Implement key block authoring and encryption
* Implement key block translation
* Implement key block component combination
* Add CPack packaging for Windows and MacOS
* Test on various ARM architectures
* Support for ISO 20038:2017 format version E

License
=======

Copyright (c) 2020, 2021 ono//connect.

This project is licensed under the terms of the LGPL v2.1 license. See LICENSE file.
