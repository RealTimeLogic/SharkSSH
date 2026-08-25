/* Transport-neutral shell and SFTP feature configuration. */

#include "sftpExample.h"
#include <string.h>

/** Build matching shell and SFTP configurations around one filesystem. */
int
SharkSshSftpExample_constructor(
   SharkSshSftpExample* example,
   const SharkSshAuthenticator* authenticator,
   const SharkSshFileSystem* fileSystem,
   const SharkSshExampleAllocator* allocator,
   U8 readOnly)
{
   int status;
   if( ! example || ! authenticator ||
      (! authenticator->password && ! authenticator->publicKey) ||
      ! fileSystem)
      return SharkSshErrArgument;
   memset(example, 0, sizeof(*example));
   example->authenticator = *authenticator;
   example->fileSystem = fileSystem;
   example->shellConfig.fileSystem = fileSystem;
   example->shellConfig.banner = "SharkSSH management shell\r\n";
   example->shellConfig.readOnly = readOnly;
   example->sftpConfig.fileSystem = fileSystem;
   example->sftpConfig.root = "";
   example->sftpConfig.readOnly = readOnly;
   status = SharkSshExampleService_constructor(
      &example->service, &example->shellConfig,
      &example->sftpConfig, allocator);
   return status;
}

/** Install the example's host key, login, filesystem, and service callbacks. */
int
SharkSshSftpExample_configure(
   SharkSshConfig* config, SharkSshRsaHostKey* rsaHostKey,
   SharkSslRSAKey privateKey, SharkSshSftpExample* example)
{
   if( ! config || ! rsaHostKey || ! privateKey || ! example ||
      ! example->fileSystem)
      return SharkSshErrArgument;
   SharkSshConfig_constructor(config);
   SharkSshRsaHostKey_constructor(rsaHostKey, privateKey);
   SharkSshRsaHostKey_set(&config->hostKey, rsaHostKey);
   config->authenticator = example->authenticator;
   config->fileSystem = example->fileSystem;
   SharkSshExampleService_install(&example->service, config);
   return SharkSshOk;
}
