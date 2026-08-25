get_filename_component(SHARKSSH_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../../.." ABSOLUTE)

set(SHARKSSL_ROOT "${SHARKSSH_ROOT}/../SharkSSL")
set(PLATFORM_ROOT "${SHARKSSH_ROOT}/examples/build/ESP32/platform")
set(EXAMPLE_ROOT "${SHARKSSH_ROOT}/examples/03-sftp")

idf_component_register(
    SRCS
        "${PLATFORM_ROOT}/sharkSshEspApplication.c"
        "${PLATFORM_ROOT}/sharkSshEspNetwork.c"
        "${PLATFORM_ROOT}/sharkSshEspPlatform.c"
        "${SHARKSSL_ROOT}/src/SharkSSL.c"
        "${SHARKSSL_ROOT}/src/selib.c"
        "${SHARKSSH_ROOT}/src/SharkSSH.c"
        "${SHARKSSH_ROOT}/src/SharkSshCrypto.c"
        "${SHARKSSH_ROOT}/src/plugins/Shell/SharkSshShell.c"
        "${SHARKSSH_ROOT}/src/plugins/Sftp/SharkSshSftp.c"
        "${SHARKSSH_ROOT}/examples/startup/selibStartup.c"
        "${EXAMPLE_ROOT}/hostFileSystem.c"
        "${EXAMPLE_ROOT}/sftpService.c"
        "${EXAMPLE_ROOT}/sftpExample.c"
        "${EXAMPLE_ROOT}/example.c"
    INCLUDE_DIRS
        "${PLATFORM_ROOT}"
        "${SHARKSSL_ROOT}/inc"
        "${SHARKSSL_ROOT}/src"
        "${SHARKSSL_ROOT}/inc/arch/FreeRTOS"
        "${SHARKSSH_ROOT}/inc"
        "${SHARKSSH_ROOT}/src/plugins/Shell"
        "${SHARKSSH_ROOT}/src/plugins/Sftp"
        "${SHARKSSH_ROOT}/examples/startup"
        "${EXAMPLE_ROOT}"
    PRIV_REQUIRES
        esp_eth esp_event esp_netif esp_system fatfs lwip wear_levelling
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    B_LITTLE_ENDIAN=1
    NO_MAIN=1
    SHARKSSH_EXAMPLE_ROOT=CONFIG_SHARKSSH_ESP_STORAGE_MOUNT_POINT
    XPRINTF=0)
