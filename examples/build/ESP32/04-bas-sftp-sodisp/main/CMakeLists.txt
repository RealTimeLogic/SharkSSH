get_filename_component(SHARKSSH_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../../.." ABSOLUTE)

set(BAS_ROOT "${SHARKSSH_ROOT}/../BAS")
set(PLATFORM_ROOT "${SHARKSSH_ROOT}/examples/build/ESP32/platform")
set(EXAMPLE_ROOT "${SHARKSSH_ROOT}/examples/03-sftp")
set(BAS_EXAMPLE_ROOT "${SHARKSSH_ROOT}/examples/04-bas-sftp")

idf_component_register(
    SRCS
        "${PLATFORM_ROOT}/sharkSshEspApplication.c"
        "${PLATFORM_ROOT}/sharkSshEspNetwork.c"
        "${PLATFORM_ROOT}/sharkSshEspPlatform.c"
        "${BAS_ROOT}/src/BWS.c"
        "${BAS_ROOT}/src/arch/FreeRTOS/ThreadLib.c"
        "${BAS_ROOT}/src/arch/NET/LwIP/SoDisp.c"
        "${BAS_ROOT}/src/DiskIo/posix/BaFile.c"
        "${SHARKSSH_ROOT}/src/SharkSSH.c"
        "${SHARKSSH_ROOT}/src/SharkSshCrypto.c"
        "${SHARKSSH_ROOT}/src/plugins/BasIo/SharkSshBasIo.c"
        "${SHARKSSH_ROOT}/src/plugins/Shell/SharkSshShell.c"
        "${SHARKSSH_ROOT}/src/plugins/Sftp/SharkSshSftp.c"
        "${SHARKSSH_ROOT}/examples/startup/soDispStartup.c"
        "${EXAMPLE_ROOT}/sftpService.c"
        "${EXAMPLE_ROOT}/sftpExample.c"
        "${BAS_EXAMPLE_ROOT}/example.c"
    INCLUDE_DIRS
        "${PLATFORM_ROOT}"
        "${BAS_ROOT}/inc"
        "${BAS_ROOT}/inc/arch/NET/LwIP"
        "${BAS_ROOT}/inc/arch/FreeRTOS"
        "$ENV{IDF_PATH}/components/freertos/FreeRTOS-Kernel/include/freertos"
        "${SHARKSSH_ROOT}/inc"
        "${SHARKSSH_ROOT}/src/plugins/BasIo"
        "${SHARKSSH_ROOT}/src/plugins/Shell"
        "${SHARKSSH_ROOT}/src/plugins/Sftp"
        "${SHARKSSH_ROOT}/examples/startup"
        "${EXAMPLE_ROOT}"
        "${BAS_EXAMPLE_ROOT}"
    PRIV_REQUIRES
        esp_eth esp_event esp_netif esp_system fatfs lwip wear_levelling
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    BA_ESP32=1
    BA_FREERTOS=1
    BA_LWIP=1
    B_LITTLE_ENDIAN=1
    NO_MAIN=1
    SHARKSSH_EXAMPLE_ROOT=CONFIG_SHARKSSH_ESP_STORAGE_MOUNT_POINT
    SHARKSSH_SODISP_CREATE_SERVER=1
    XPRINTF=0)
