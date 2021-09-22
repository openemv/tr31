TR-31 library and tools
=======================

This library is an implementation of the ASC X9 TR-31 standard. Given that
most uses of this standard involve dedicated security hardware, this
implementation is mostly for validation and debugging purposes.

Features
========

Currently this library implements parsing and decryption of TR-31 format
version A, B, and C. Various helper functions are also available to stringify
TR-31 header attributes.

Roadmap
=======

* Implement TR-31 format version D decryption and verification
* Implement key block authoring and encryption
* Implement key block translation
* Implement key block component combination
* Add CPack packaging for Windows and MacOS
* Test on various ARM architectures

License
=======

Copyright (c) 2020, 2021 ono//connect.

This project is licensed under the terms of the LGPL v2.1 license. See LICENSE file.
