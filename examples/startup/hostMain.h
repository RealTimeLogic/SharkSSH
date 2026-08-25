#ifndef _SharkSshExampleHostMain_h
#define _SharkSshExampleHostMain_h

/* Shared host-only support for the optional selib and SoDisp entry points. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY
#define SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY 0
#endif /* SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY */

#if !SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY
#include "exampleHostKey.h"
#endif /* !SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY */

/** Host-only state shared by the optional selib and SoDisp entry points. */
typedef struct
{
   SharkSslRSAKey privateKey; /**< Parsed or built-in example host key. */
   U16 port; /**< Requested listening port. */
} SharkSshExampleHost;

/**
 * Fill the SharkSSL seed buffer from the operating system random source.
 *
 * @param context Unused host entropy context.
 * @param buffer Destination buffer.
 * @param size Number of random bytes required.
 * @return @ref SharkSshOk on success, or @ref SharkSshErrCrypto.
 */
static int
sharkSshExampleGetEntropy(void* context, U8* buffer, U32 size)
{
   (void)context;
   if( ! buffer || ! size)
      return SharkSshErrArgument;

#ifdef _WIN32
   while(size)
   {
      unsigned int value;
      U32 chunk = size < sizeof(value) ? size : (U32)sizeof(value);
      if(rand_s(&value))
         return SharkSshErrCrypto;
      memcpy(buffer, &value, chunk);
      buffer += chunk;
      size -= chunk;
   }
#else
   FILE* file = fopen("/dev/urandom", "rb");
   if( ! file || fread(buffer, 1, size, file) != size)
   {
      if(file)
         fclose(file);
      return SharkSshErrCrypto;
   }
   fclose(file);
#endif /* _WIN32 */
   return SharkSshOk;
}

/**
 * Parse and range-check a decimal TCP port.
 *
 * @param text NUL-terminated decimal text.
 * @param port Receives a value from 1 through 65535.
 * @return @ref SharkSshOk when valid, otherwise @ref SharkSshErrArgument.
 */
static int
sharkSshExampleParsePort(const char* text, U16* port)
{
   char* end;
   unsigned long value;
   if( ! text || ! text[0] || ! port)
      return SharkSshErrArgument;
   value = strtoul(text, &end, 10);
   if(*end || ! value || value > 65535)
      return SharkSshErrArgument;
   *port = (U16)value;
   return SharkSshOk;
}

#if SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY
/**
 * Load a small PEM file into a newly allocated NUL-terminated buffer.
 *
 * @param path Host path to read.
 * @return Allocated file contents, or `NULL` on failure. The caller frees it.
 */
static char*
sharkSshExampleLoadFile(const char* path)
{
   FILE* file;
   char* data;
   long size;
   file = fopen(path, "rb");
   if( ! file)
      return 0;
   if(fseek(file, 0, SEEK_END) || (size = ftell(file)) <= 0 ||
      size > 65535 || fseek(file, 0, SEEK_SET))
   {
      fclose(file);
      return 0;
   }
   data = (char*)malloc((size_t)size + 1);
   if( ! data || fread(data, 1, (size_t)size, file) != (size_t)size)
   {
      free(data);
      fclose(file);
      return 0;
   }
   fclose(file);
   data[size] = 0;
   return data;
}
#endif /* SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY */

/**
 * Parse common host arguments and prepare the example's RSA private key.
 *
 * @param host Structure to initialize.
 * @param argc Command-line argument count.
 * @param argv Command-line argument vector.
 * @return @ref SharkSshOk on success, or a negative status.
 */
static int
SharkSshExampleHost_constructor(SharkSshExampleHost* host,
                                int argc, char** argv)
{
   if( ! host || ! argv)
      return SharkSshErrArgument;
   memset(host, 0, sizeof(*host));
   host->port = 22;

#if SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY
   {
      char* pem;
      if(argc < 2 || argc > 3 ||
         (argc == 3 && sharkSshExampleParsePort(argv[2], &host->port)))
      {
         fprintf(stderr, "Usage: %s host-key.pem [port]\n", argv[0]);
         return SharkSshErrArgument;
      }
      pem = sharkSshExampleLoadFile(argv[1]);
      if( ! pem)
         return SharkSshErrCrypto;
      host->privateKey = sharkssl_PEM_to_RSAKey(pem, 0);
      memset(pem, 0, strlen(pem));
      free(pem);
      if( ! host->privateKey)
         return SharkSshErrCrypto;
   }
#else
   if(argc > 2 ||
      (argc == 2 && sharkSshExampleParsePort(argv[1], &host->port)))
   {
      fprintf(stderr, "Usage: %s [port]\n", argv[0]);
      return SharkSshErrArgument;
   }
   host->privateKey = (SharkSslRSAKey)sharkSshExampleHostKey;
#endif /* SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY */

#ifdef _WIN32
   {
      WSADATA wsaData;
      if(WSAStartup(MAKEWORD(2,2), &wsaData))
         return SharkSshErrSocket;
   }
#endif /* _WIN32 */
   return SharkSshOk;
}

#endif /* _SharkSshExampleHostMain_h */
