#include "sharkSshEspPlatform.h"

#include <esp_err.h>
#include <esp_eth.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <sdkconfig.h>
#include <soc/soc_caps.h>

/* Applications may replace this weak hook for Wi-Fi or SPI Ethernet. */
#if SOC_EMAC_SUPPORTED

static const char* networkTag = "SharkSSH-network";
static EventGroupHandle_t networkEvents;
static const EventBits_t networkGotIp = BIT0;

/** Log Ethernet link changes and clear readiness when the link drops. */
static void
networkEthernetEvent(void* context, esp_event_base_t eventBase,
                     int32_t eventId, void* eventData)
{
   (void)context;
   (void)eventBase;
   (void)eventData;
   if(eventId == ETHERNET_EVENT_CONNECTED)
      ESP_LOGI(networkTag, "Ethernet link up");
   else if(eventId == ETHERNET_EVENT_DISCONNECTED)
   {
      ESP_LOGI(networkTag, "Ethernet link down");
      xEventGroupClearBits(networkEvents, networkGotIp);
   }
}

/** Log the acquired IPv4 address and release the startup wait. */
static void
networkGotIpEvent(void* context, esp_event_base_t eventBase,
                  int32_t eventId, void* eventData)
{
   ip_event_got_ip_t* event = (ip_event_got_ip_t*)eventData;
   (void)context;
   (void)eventBase;
   (void)eventId;
   ESP_LOGI(networkTag, "IPv4 address " IPSTR,
            IP2STR(&event->ip_info.ip));
   xEventGroupSetBits(networkEvents, networkGotIp);
}

/** Configure the internal EMAC, start Ethernet, and wait for an IPv4 address. */
__attribute__((weak)) int
SharkSshEspNetwork_start(void)
{
   eth_mac_config_t macConfig = ETH_MAC_DEFAULT_CONFIG();
   eth_phy_config_t phyConfig = ETH_PHY_DEFAULT_CONFIG();
   eth_esp32_emac_config_t emacConfig = ETH_ESP32_EMAC_DEFAULT_CONFIG();
   esp_eth_config_t driverConfig;
   esp_eth_mac_t* mac;
   esp_eth_phy_t* phy;
   esp_eth_handle_t handle = 0;
   esp_netif_config_t netifConfig = ESP_NETIF_DEFAULT_ETH();
   esp_netif_t* netif;
   esp_eth_netif_glue_handle_t glue;
   esp_err_t status;

   phyConfig.phy_addr = CONFIG_SHARKSSH_ESP_ETH_PHY_ADDR;
   phyConfig.reset_gpio_num = CONFIG_SHARKSSH_ESP_ETH_PHY_RST_GPIO;
   emacConfig.smi_gpio.mdc_num = CONFIG_SHARKSSH_ESP_ETH_MDC_GPIO;
   emacConfig.smi_gpio.mdio_num = CONFIG_SHARKSSH_ESP_ETH_MDIO_GPIO;
   emacConfig.interface = EMAC_DATA_INTERFACE_RMII;
   emacConfig.clock_config.rmii.clock_mode = EMAC_CLK_EXT_IN;
   emacConfig.clock_config.rmii.clock_gpio =
      CONFIG_SHARKSSH_ESP_ETH_RMII_CLK_GPIO;
#if SOC_EMAC_USE_MULTI_IO_MUX
   emacConfig.emac_dataif_gpio.rmii.tx_en_num =
      CONFIG_SHARKSSH_ESP_ETH_RMII_TX_EN_GPIO;
   emacConfig.emac_dataif_gpio.rmii.txd0_num =
      CONFIG_SHARKSSH_ESP_ETH_RMII_TXD0_GPIO;
   emacConfig.emac_dataif_gpio.rmii.txd1_num =
      CONFIG_SHARKSSH_ESP_ETH_RMII_TXD1_GPIO;
   emacConfig.emac_dataif_gpio.rmii.crs_dv_num =
      CONFIG_SHARKSSH_ESP_ETH_RMII_CRS_DV_GPIO;
   emacConfig.emac_dataif_gpio.rmii.rxd0_num =
      CONFIG_SHARKSSH_ESP_ETH_RMII_RXD0_GPIO;
   emacConfig.emac_dataif_gpio.rmii.rxd1_num =
      CONFIG_SHARKSSH_ESP_ETH_RMII_RXD1_GPIO;
#endif /* SOC_EMAC_USE_MULTI_IO_MUX */

   mac = esp_eth_mac_new_esp32(&emacConfig, &macConfig);
   phy = esp_eth_phy_new_generic(&phyConfig);
   if( ! mac || ! phy)
      return ESP_ERR_NO_MEM;
   driverConfig = (esp_eth_config_t)ETH_DEFAULT_CONFIG(mac, phy);
   status = esp_eth_driver_install(&driverConfig, &handle);
   if(status != ESP_OK)
      return status;
   status = esp_netif_init();
   if(status != ESP_OK)
      return status;
   status = esp_event_loop_create_default();
   if(status != ESP_OK)
      return status;
   netif = esp_netif_new(&netifConfig);
   glue = esp_eth_new_netif_glue(handle);
   if( ! netif || ! glue)
      return ESP_ERR_NO_MEM;
   status = esp_netif_attach(netif, glue);
   if(status != ESP_OK)
      return status;
   networkEvents = xEventGroupCreate();
   if( ! networkEvents)
      return ESP_ERR_NO_MEM;
   status = esp_event_handler_register(
      ETH_EVENT, ESP_EVENT_ANY_ID, networkEthernetEvent, 0);
   if(status != ESP_OK)
      return status;
   status = esp_event_handler_register(
      IP_EVENT, IP_EVENT_ETH_GOT_IP, networkGotIpEvent, 0);
   if(status != ESP_OK)
      return status;
   status = esp_eth_start(handle);
   if(status != ESP_OK)
      return status;
   xEventGroupWaitBits(networkEvents, networkGotIp,
                       pdFALSE, pdTRUE, portMAX_DELAY);
   return ESP_OK;
}

#else /* !SOC_EMAC_SUPPORTED */

/**
 * Report that the default network hook cannot support this ESP target.
 *
 * Applications for these targets replace this weak function with board
 * network initialization.
 *
 * @return `ESP_ERR_NOT_SUPPORTED`.
 */
__attribute__((weak)) int
SharkSshEspNetwork_start(void)
{
   return ESP_ERR_NOT_SUPPORTED;
}

#endif /* SOC_EMAC_SUPPORTED */
