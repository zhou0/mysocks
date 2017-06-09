Mysocks


[![GitHub version](https://badge.fury.io/gh/zhou0%2Fmysocks.svg)](https://badge.fury.io/gh/zhou0%2Fmysocks)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a457935ff4474195a171d11ebb79dc13)](https://www.codacy.com/app/zhou0/mysocks?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=zhou0/mysocks&amp;utm_campaign=Badge_Grade)
[![Build Status](https://travis-ci.org/zhou0/mysocks.svg?branch=master)](https://travis-ci.org/zhou0/mysocks)
[![Build status](https://ci.appveyor.com/api/projects/status/okfccad7f94s0ex7?svg=true)](https://ci.appveyor.com/project/zhou0/tinysocks)[![Coverage Status](https://coveralls.io/repos/github/zhou0/mysocks/badge.svg?branch=master)](https://coveralls.io/github/zhou0/mysocks?branch=master)
<a href="https://scan.coverity.com/projects/zhou0-mysocks">
  <img alt="Coverity Scan Build Status"
       src="https://img.shields.io/coverity/scan/12236.svg"/>
</a>
[![](https://images.microbadger.com/badges/image/fgfw/mysocks.svg)](https://microbadger.com/images/fgfw/mysocks "Get your own image badge on microbadger.com")
[![](https://images.microbadger.com/badges/version/fgfw/mysocks.svg)](https://microbadger.com/images/fgfw/mysocks "Get your own version badge on microbadger.com")

Mysocks project provides three executables,namely ssclient, ssclient-openssl and ssclient-wolfssl. Supported Platform:Unix,Windows,Linux and Mac OS X. Win32 binaries are provided, You can compile from source on other platforms. 
```
ssclient supports rc4-md5 encryption method only.

ssclient-openssl supports the following 17 encryption methods:
                        aes-128-cfb,aes-128-ctr,aes-128-ofb
			aes-192-cfb,aes-192-ctr,aes-192-ofb
			aes-256-cfb,aes-256-ctr,aes-256-ofb
			camellia-128-cfb,camellia-128-ofb
			camellia-192-cfb,camellia-192-ofb
			camellia-256-cfb,camellia-256-ofb
			rc4-md5

ssclient-wolfssl supports the following 19 encryption methods ( including AEAD )
                        aes-128-cbc,aes-128-ccm,aes-128-ctr,aes-128-gcm
                        aes-192-cbc,aes-192-ccm,aes-192-ctr,aes-192-gcm
			aes-256-cbc,aes-256-ccm,aes-256-ctr,aes-256-gcm
			camellia-128-cbc,camellia-256-cbc
			chacha20-ietf,hc-128,rabbit
			chacha20-ietf-poly1305
			rc4-md5

aes-128-ccm is alias for AEAD_AES_128_CCM
aes-128-gcm is alias for AEAD_AES_128_GCM
aes-192-ccm is alias for AEAD_AES_192_CCM
aes-192-gcm is alias for AEAD_AES_192_GCM
aes-256-ccm is alias for AEAD_AES_256_CCM
aes-256-gcm is alias for AEAD_AES_256_GCM
chacha20-ietf-poly1305 is alias for AEAD_CHACHA20_POLY1305
```
