#ifndef _SharkSshEspPlatform_h
#define _SharkSshEspPlatform_h

#include <SharkSSH.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Start the board network and wait until it has an IPv4 address.
 *
 * The supplied weak implementation supports the ESP internal EMAC. A board
 * application may replace it for Wi-Fi or an external Ethernet controller.
 *
 * @return `ESP_OK` on success, otherwise an ESP-IDF error code.
 */
int SharkSshEspNetwork_start(void);
/**
 * Mount the example FAT filesystem at the configured mount point.
 * @return `ESP_OK` on success, otherwise an ESP-IDF error code.
 */
int SharkSshEspStorage_mount(void);
/**
 * Fill SharkSSL's seed buffer using the ESP hardware random generator.
 *
 * @param context Unused platform context.
 * @param buffer Destination buffer.
 * @param size Number of random bytes required.
 * @return @ref SharkSshOk on success, or @ref SharkSshErrArgument.
 */
int SharkSshEspEntropy_get(void* context, U8* buffer, U32 size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SharkSshEspPlatform_h */
