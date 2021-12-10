# OpenVatsimAuth

An open source reverse-engineered alternative to `libvatsimauth` as required
for VATSIM clients.

The reverse engineering process for this library is detailed
[here](./revenge.md).

## Compiling

Link against `libcrypto` from OpenSSL, this is used for md5 hashing and random
number generation, it should be easy to swap out if necessary.

Compiles with `--std=c++11`.

Tested on x86_64 Linux.
