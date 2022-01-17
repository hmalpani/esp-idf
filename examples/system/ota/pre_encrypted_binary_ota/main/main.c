/*
 * SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
/* Pre-encrypted binary OTA example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_encrypted_img.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_http_client.h"
#include "protocol_examples_common.h"
#include "esp_ota_ops.h"

static const char *TAG = "sample_application";

extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[]  asm("_binary_ca_cert_pem_end");

extern const uint8_t rsa_private_pem_start[] asm("_binary_test_rsa_private_key_pem_start");
extern const uint8_t rsa_private_pem_end[]   asm("_binary_test_rsa_private_key_pem_end");

static esp_err_t _ota_write(esp_ota_handle_t update_handle, const void *buffer, size_t buf_len)
{
    if (buffer == NULL) {
        return ESP_FAIL;
    }
    esp_err_t err = esp_ota_write(update_handle, buffer, buf_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error: esp_ota_write failed! err=0x%x", err);
    } else {
        ESP_LOGD(TAG, "Written image length %d", buf_len);
        err = ESP_OK;
    }
    return err;
}

void task(void *pvParam)
{
    esp_err_t err;
    esp_http_client_config_t config = {
        .url = CONFIG_EXAMPLE_FIRMWARE_UPGRADE_URL,
        .cert_pem = (const char *) server_cert_pem_start,
        .cert_len = server_cert_pem_end - server_cert_pem_start,
    };

    esp_http_client_handle_t http_client = esp_http_client_init(&config);
    if  (http_client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        goto exit;
    }

    err = esp_http_client_set_method(http_client, HTTP_METHOD_GET);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_http_client_set_method: returned -0x%04x\n", (unsigned int) - err);
    }

    err = esp_http_client_open(http_client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        goto exit;
    }

    int content_length = esp_http_client_fetch_headers(http_client);
    if (content_length < 0) {
        ESP_LOGE(TAG, "HTTP client fetch headers failed");
        goto exit;
    }

    esp_ota_handle_t update_handle;
    const esp_partition_t *update_partition = NULL;
    update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        ESP_LOGE(TAG, "Passive OTA partition not found");
        err = ESP_FAIL;
        goto exit;
    }

    esp_decrypt_cfg_t cfg = {
        .rsa_pub_key = (char *)rsa_private_pem_start,
        .rsa_pub_key_len = rsa_private_pem_end - rsa_private_pem_start,
    };
    esp_decrypt_handle_t *ctx = esp_encrypted_img_decrypt_start(&cfg);
    if (ctx == NULL) {
        goto exit;
    }
    pre_enc_decrypt_arg_t *args = calloc(1, sizeof(pre_enc_decrypt_arg_t));
    if (!args) {
        ESP_LOGE(TAG, "Failed to allocate memory");
        goto exit;
    }
    int http_read_buf_size = 1000;
    args->data_in = malloc(http_read_buf_size);
    if (!args->data_in) {
        ESP_LOGE(TAG, "Failed to allocate memory");
        goto exit;
    }

    err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
    }

    int data_read = 0;
    do {
        data_read = esp_http_client_read(http_client, args->data_in, http_read_buf_size);
        if (data_read > 0) {
            args->data_in_len = data_read;
            err = esp_encrypted_img_decrypt_data(ctx, args);
            if (err == ESP_FAIL) {
                ESP_LOGE(TAG, "Error in decoding binary");
                break;
            }
            if (args->data_out_len > 0) {
                if (_ota_write(update_handle, (const void *)args->data_out, args->data_out_len) != ESP_OK) {
                    ESP_LOGE(TAG, "Error occured while writing OTA update data to partition");
                    break;
                }
            }
        }
    } while (err != ESP_OK);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "OTA Successful\n");
        err = esp_encrypted_img_decrypt_end(ctx);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Error");
        }
        esp_http_client_close(http_client);
        if (update_partition != NULL) {
            err = esp_ota_set_boot_partition(update_partition);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "esp_ota_set_boot_partition failed! err=0x%x, %s", err, esp_err_to_name(err));
                goto exit;
            }
            for (int i = 5; i >= 0; i--) {
                vTaskDelay(1000 / portTICK_PERIOD_MS);
                printf("Restarting in %d second.\n", i);
            }
            esp_restart();
        }
    } else {
        ESP_LOGE(TAG, "OTA failed");
        esp_encrypted_img_decrypt_end(ctx);
    }

exit:
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect());

    xTaskCreate(&task, "decode_example_task", 8192, NULL, 5, NULL);

}
