// SPDX-License-Identifier: MIT

// Some handy strings for specifying xfrm encryption/authentication/compression algorithms.
// Current as of Linux 5.18.10

// Authentication/Integrity
pub const AUTH_ALG_NULL: &str = "digest_null";
pub const AUTH_ALG_MD5_HMAC: &str = "hmac(md5)";
pub const AUTH_ALG_SHA1_HMAC: &str = "hmac(sha1)";
pub const AUTH_ALG_SHA2_256_HMAC: &str = "hmac(sha256)";
pub const AUTH_ALG_SHA2_384_HMAC: &str = "hmac(sha384)";
pub const AUTH_ALG_SHA2_512_HMAC: &str = "hmac(sha512)";
pub const AUTH_ALG_RIPEMD_160_HMAC: &str = "hmac(rmd160)";
pub const AUTH_ALG_AES_XCBC: &str = "xcbc(aes)";
pub const AUTH_ALG_AES_CMAC: &str = "cmac(aes)";
pub const AUTH_ALG_SM3_HMAC: &str = "hmac(sm3)";

// Compression
pub const COMP_ALG_DEFLATE: &str = "deflate";
pub const COMP_ALG_LZS: &str = "lzs";
pub const COMP_ALG_LZJH: &str = "lzjh";

// Encryption
pub const ENC_ALG_NULL: &str = "ecb(cipher_null)";
pub const ENC_ALG_DES_CBC: &str = "cbc(des)";
pub const ENC_ALG_3DES_CBC: &str = "cbc(des3_ede)";
pub const ENC_ALG_CAST_CBC: &str = "cbc(cast5)";
pub const ENC_ALG_BLOWFISH_CBC: &str = "cbc(blowfish)";
pub const ENC_ALG_AES_CBC: &str = "cbc(aes)";
pub const ENC_ALG_SERPENT_CBC: &str = "cbc(serpent)";
pub const ENC_ALG_CAMELLIA_CBC: &str = "cbc(camellia)";
pub const ENC_ALG_TWOFISH_CBC: &str = "cbc(twofish)";
pub const ENC_ALG_AES_CTR: &str = "rfc3686(ctr(aes))";
pub const ENC_ALG_SM4_CBC: &str = "cbc(sm4)";

// Encryption (AEAD)
pub const ENC_AEAD_ALG_AES_GCM: &str = "rfc4106(gcm(aes))";
pub const ENC_AEAD_ALG_AES_CCM: &str = "rfc4309(ccm(aes))";
pub const ENC_AEAD_ALG_NULL_AES_GMAC: &str = "rfc4543(gcm(aes))";
pub const ENC_AEAD_ALG_CHACHA20_POLY1305: &str = "rfc7539esp(chacha20,poly1305)";
