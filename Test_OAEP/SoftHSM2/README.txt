SoftHSM2 for Windows
====================

SoftHSM is an implementation of a cryptographic store accessible through 
a PKCS#11 interface. You can use it to explore PKCS#11 without having 
a Hardware Security Module. It is being developed as a part of the OpenDNSSEC 
project:

  https://www.opendnssec.org/softhsm/

This package includes both 32-bit and 64-bit build of SoftHSM 2.5.0 statically 
linked to OpenSSL 1.1.1. Latest version of SoftHSM2 for Windows can be 
downloaded from:

  https://github.com/disig/SoftHSM2-for-Windows

SoftHSM2 searches for its configuration file in the following locations:

  1. Path specified by SOFTHSM2_CONF environment variable
  2. User specific path %HOMEDRIVE%%HOMEPATH%\softhsm2.conf
  3. File softhsm2.conf in the current working directory

Following modifications of environment variables are required before using 
portable (not installed from MSI) version extracted in C:\SoftHSM2\ directory:

  set SOFTHSM2_CONF=C:\SoftHSM2\etc\softhsm2.conf
  set PATH=%PATH%;C:\SoftHSM2\lib\

First token can be initialized with PKCS#11 function C_InitToken or with 
the following command:

  softhsm2-util.exe --init-token --slot 0 --label "My token 1"
