idf_component_register(SRCS "Myconsole.c"
                       INCLUDE_DIRS "include"
                       REQUIRES driver soc freertos log heap nvs_flash esp_wifi)