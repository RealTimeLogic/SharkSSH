#include "sharkSshEspPlatform.h"

#include <esp_random.h>
#include <esp_vfs_fat.h>
#include <sdkconfig.h>
#include <wear_levelling.h>

/** Fill the requested buffer using the ESP hardware random generator. */
int
SharkSshEspEntropy_get(void* context, U8* buffer, U32 size)
{
   (void)context;
   if( ! buffer || ! size)
      return SharkSshErrArgument;
   esp_fill_random(buffer, size);
   return SharkSshOk;
}

/** Mount the configured wear-levelled FAT partition once per boot. */
int
SharkSshEspStorage_mount(void)
{
   static wl_handle_t storage = WL_INVALID_HANDLE;
   esp_vfs_fat_mount_config_t config = {
      .format_if_mount_failed =
         CONFIG_SHARKSSH_ESP_FORMAT_STORAGE_IF_MOUNT_FAILED,
      .max_files = CONFIG_SHARKSSH_ESP_MAX_OPEN_FILES,
      .allocation_unit_size = 4096
   };
   if(storage != WL_INVALID_HANDLE)
      return ESP_OK;
   return esp_vfs_fat_spiflash_mount_rw_wl(
      CONFIG_SHARKSSH_ESP_STORAGE_MOUNT_POINT,
      "storage", &config, &storage);
}
