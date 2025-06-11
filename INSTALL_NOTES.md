# Installation Notes

Some rough notes for installing Cryptoki and the requisite SoftHSMv2 for testing

## MacOS Installation of Cryptoki crate and SoftHSMv2 for testing purposes

Below is a rough guide to the installation flow for Cryptoki and for the required SoftHSMv2 dependency to support the
execution of the Cryptoki test suite where Homebrew is used as the package manager. These are rough notes developed
on macOS Sequoia 15.5 with Homebrew 4.5.6 on a Macbook M1 Pro with a bash shell
(version 5.2.37(1)-release (aarch64-apple-darwin24.2.0)).

## SoftHSMv2 Installation

SoftHSMv2 is required for Cryptoki test suite execution.  Below are the rough steps required to install, build, and
check SoftHWMv2 on macOS using Homebrew. Some hoops were jumped through to manually disable DES tests which were causing
issue. The result was a clean make check excepting some PKCS#11 DES check failures.

> *NOTE* The `--pin` and `--so-pin` values are hard coded in the Cryptoki test suite to the values used below.

```bash
$ cd ~/code
$ gh repo clone softhsm/SoftHSMv2
$ brew install automake cppunit
$ brew reinstall autoconf automake
$ export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/cppunit/include"
$ export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/cppunit/lib"
$ mkdir -p ~/softhsm2/tokens
$ echo "directories.tokendir = $HOME/softhsm2/tokens" > ~/softhsm2/softhsm2.conf
$ export SOFTHSM2_CONF=$HOME/softhsm2/softhsm2.conf
$ ./src/bin/util/softhsm2-util --init-token --slot 0 --label "TestToken" --so-pin abcdef --pin fedcba --module ./src/lib/.libs/libsofthsm2.so
$ vi openssl.cnf
```

Create an openssl.cnf file with the following contents:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
```

Continuing...

```bash
$ export OPENSSL_CONF=/full/path/to/openssl.cnf
$ make distclean
$ cd src/lib/crypto/test
$ mv DESTests.cpp DESTests.cpp.disabled
$ vi Makefile.am
```

Remove the DESTests.cpp line.

Continuing...

```bash
$ cd -
$ autoreconf -fvi
$ ./autogen.sh
$ ./configure --with-crypto-backend=openssl --enable-des
$ make clean
$ make -j$(sysctl -n hw.ncpu)
$ make check
```

## Cryptoki Installation, Build, and Test

```bash
$ cd ~/code
$ gh repo clone parallaxsecond/rust-cryptoki
$ cd rust-cryptoki/
$ export TEST_PKCS11_MODULE=~/code/SoftHSMv2/src/lib/.libs/libsofthsm2.so
$ cargo build
$ cargo test
```

## Resetting the SoftHSMv2 Configuration

If you need to reset the SoftHSM configuration (like to change a pin, slot, etc.) you can:

```bash
$ rm -rf $HOME/softhsm2/
$ echo "directories.tokendir = $HOME/softhsm2/tokens" > $HOME/softhsm2/softhsm2.conf
$ export SOFTHSM2_CONF=$HOME/softhsm2/softhsm2.conf
$ rm -rf $HOME/softhsm2/tokens
$ mkdir -p $HOME/softhsm2/tokens
$ ./src/bin/util/softhsm2-util --show-slots --module ./src/lib/.libs/libsofthsm2.so
$ ./src/bin/util/softhsm2-util --init-token --slot 0 --label "TestToken" --so-pin abcdef --pin fedcba --module ./src/lib/.libs/libsofthsm2.so
```