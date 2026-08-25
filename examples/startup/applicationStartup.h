#ifndef _SharkSshApplicationStartup_h
#define _SharkSshApplicationStartup_h

/* Shared permanent-lifetime initialization used by both transports. */

#include "SharkSshExample.h"
#include <string.h>

/**
 * Seed SharkSSL and construct the permanent context for a feature example.
 *
 * The temporary entropy buffer is erased before this helper returns.
 *
 * @param application Complete startup callbacks and host key.
 * @param exampleContext Receives the constructed example context.
 * @return @ref SharkSshOk on success, or a negative status.
 */
static int
sharkSshApplicationPrepare(const SharkSshApplicationConfig* application,
                           void** exampleContext)
{
   U32 entropy[16];
   U32 i;
   int status;
   if( ! application || ! application->privateKey ||
      ! application->getEntropy || ! application->constructExample ||
      ! exampleContext)
      return SharkSshErrArgument;
   *exampleContext = 0;
   status = application->getEntropy(
      application->entropyContext, (U8*)entropy, (U32)sizeof(entropy));
   if( ! status)
   {
      for(i = 0; i < sizeof(entropy) / sizeof(entropy[0]); ++i)
         (void)sharkssl_entropy(entropy[i]);
   }
   memset(entropy, 0, sizeof(entropy));
   return status ? status : application->constructExample(exampleContext);
}

#endif /* _SharkSshApplicationStartup_h */
