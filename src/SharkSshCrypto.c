/*
 *                 SharkSSH Embedded SSH Server
 ****************************************************************************
 *   SHARKSSL CRYPTO ADAPTER
 *
 *   SharkSSL cryptographic operations used by the SSH protocol are isolated
 *   in this adapter.
 ****************************************************************************
 */

#include "SharkSshPriv.h"
#include <string.h>

static int
sharkSshRsaPublicKey(void* context, U8* data, U16 capacity, U16* size)
{
   SharkSshRsaHostKey* hostKey = (SharkSshRsaHostKey*)context;
   SharkSshWriter writer;
   U8 keyType;
   U8 isPrivate;
   U8* modulus;
   U8* exponent;
   U16 modulusLen;
   U16 exponentLen;

   if( ! hostKey || ! hostKey->privateKey || ! data || ! size)
      return SharkSshErrArgument;

   if( ! SharkSslKey_vectSize_keyInfo(
          (SharkSslKey)hostKey->privateKey, &keyType, &isPrivate,
          &modulus, &modulusLen, &exponent, &exponentLen) ||
       keyType != SHARKSSL_KEYTYPE_RSA || ! isPrivate)
      return SharkSshErrCrypto;

   sharkSshWriter_constructor(&writer, data, capacity);
   sharkSshWriter_cstring(&writer, "ssh-rsa");
   sharkSshWriter_mpint(&writer, exponent, exponentLen);
   sharkSshWriter_mpint(&writer, modulus, modulusLen);
   if(writer.status)
      return writer.status;
   *size = (U16)sharkSshWriter_size(&writer);
   return SharkSshOk;
}

static int
sharkSshRsaSignHash(void* context, const U8 hash[32], U8* signature,
                    U16 capacity, U16* size)
{
   SharkSshRsaHostKey* hostKey = (SharkSshRsaHostKey*)context;
   U16 signatureLen;

   if( ! hostKey || ! hostKey->privateKey || ! hash ||
       ! signature || ! size)
      return SharkSshErrArgument;
   signatureLen = SharkSslRSAKey_size(hostKey->privateKey);
   if(signatureLen > capacity)
      return SharkSshErrBounds;
   if(sharkssl_RSA_PKCS1V1_5_sign_hash(
         hostKey->privateKey, signature, &signatureLen,
         hash, SHARKSSL_HASHID_SHA256) != SHARKSSL_RSA_OK)
      return SharkSshErrCrypto;
   *size = signatureLen;
   return SharkSshOk;
}

void
SharkSshRsaHostKey_constructor(SharkSshRsaHostKey* hostKey,
                               SharkSslRSAKey privateKey)
{
   if(hostKey)
      hostKey->privateKey = privateKey;
}

void
SharkSshRsaHostKey_set(SharkSshHostKey* target,
                       SharkSshRsaHostKey* hostKey)
{
   if(target)
   {
      target->context = hostKey;
      target->publicKey = sharkSshRsaPublicKey;
      target->signHash = sharkSshRsaSignHash;
   }
}

int
SharkSshHostKey_fingerprint(const SharkSshHostKey* hostKey,
                            U8 fingerprint[32])
{
   U8 publicKey[SHARKSSH_MAX_HOST_KEY_LEN];
   U16 publicKeySize = 0;
   SharkSslSha256Ctx hash;
   int status;
   if( ! hostKey || ! hostKey->publicKey || ! fingerprint)
      return SharkSshErrArgument;
   status = hostKey->publicKey(hostKey->context, publicKey,
                               sizeof(publicKey), &publicKeySize);
   if(status || ! publicKeySize || publicKeySize > sizeof(publicKey))
   {
      memset(publicKey, 0, sizeof(publicKey));
      if( ! status)
         status = SharkSshErrCrypto;
      return status;
   }
   SharkSslSha256Ctx_constructor(&hash);
   SharkSslSha256Ctx_append(&hash, publicKey, publicKeySize);
   SharkSslSha256Ctx_finish(&hash, fingerprint);
   memset(publicKey, 0, sizeof(publicKey));
   return SharkSshOk;
}

int
sharkSshX25519(U8 privateKey[32], U8 publicKey[32],
               const U8 peerPublicKey[32], U8 sharedSecret[32])
{
   if( ! privateKey || ! publicKey || ! peerPublicKey || ! sharedSecret)
      return SharkSshErrArgument;

   if(sharkssl_X25519_createKeyPair(privateKey, publicKey))
      return SharkSshErrCrypto;
   if(sharkssl_X25519_sharedSecret(privateKey, peerPublicKey, sharedSecret))
      return SharkSshErrCrypto;
   return SharkSshOk;
}
