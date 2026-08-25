#include "sharkSshEspPlatform.h"

#include "SharkSshExample.h"
#include "exampleHostKey.h"
#include <esp_err.h>
#include <esp_log.h>
#include <sdkconfig.h>
#include <string.h>
#include <stdlib.h>

#if SHARKSSL_BA
#include "soDispStartup.h"
#else
#include "selibStartup.h"
#endif /* SHARKSSL_BA */

static const char* applicationTag = "SharkSSH";

#if !SHARKSSL_BA
/** Log a standalone SharkSSL assertion and stop the failed firmware task. */
void
sharkAssert(const char* file, int line)
{
   ESP_LOGE(applicationTag, "SharkSSL assertion at %s:%d", file, line);
   abort();
}
#endif /* !SHARKSSL_BA */

/**
 * ESP-IDF entry point shared by the selib and SoDisp feature projects.
 *
 * It mounts storage, starts the board network, fills the common application
 * callbacks, then calls the same startup module used by host examples.
 */
void
app_main(void)
{
   SharkSshApplicationConfig application;
   int status;

   status = SharkSshEspStorage_mount();
   if(status != ESP_OK)
   {
      ESP_LOGE(applicationTag, "FAT storage mount failed: %s",
               esp_err_to_name(status));
      return;
   }
   ESP_LOGI(applicationTag, "SFTP root mounted at %s",
            CONFIG_SHARKSSH_ESP_STORAGE_MOUNT_POINT);

   status = SharkSshEspNetwork_start();
   if(status != ESP_OK)
   {
      ESP_LOGE(applicationTag,
               "Network startup failed: %s; override "
               "SharkSshEspNetwork_start for this board",
               esp_err_to_name(status));
      return;
   }

   memset(&application, 0, sizeof(application));
   application.privateKey = (SharkSslRSAKey)sharkSshExampleHostKey;
   application.getEntropy = SharkSshEspEntropy_get;
   application.constructExample = SharkSshExample_constructor;
   application.port = CONFIG_SHARKSSH_ESP_PORT;
#if SHARKSSL_BA
   application.maxConnections = CONFIG_SHARKSSH_ESP_MAX_CONNECTIONS;
#endif /* SHARKSSL_BA */

   ESP_LOGI(applicationTag,
            "SSH ready on port %u (testuser / test-password)",
            (unsigned)application.port);
#if SHARKSSL_BA
   status = SharkSshSoDispStartup_runApplication(&application);
#else
   status = SharkSshSelibStartup_runApplication(0, &application);
#endif /* SHARKSSL_BA */
   if(status)
      ESP_LOGE(applicationTag, "SSH server stopped: %d", status);
}
