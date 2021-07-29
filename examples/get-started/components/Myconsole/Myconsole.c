#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_system.h"
#include "driver/uart.h"
#include "esp_vfs.h"
#include "esp_vfs_dev.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#include "esp_heap_task_info.h"
#include "esp_heap_caps.h"

#include "Myconsole.h"

static const char* TAG = "CONSOLE";

//Variable to store command entered by user and length of command
static char command[50];
static int command_length = 0;

static int num_commands = 6;
static int max_commands = 10;
static char* commands_info[10][2];

#define MAX_TASK_NUM 20                         // Max number of per tasks info that it can store
#define MAX_BLOCK_NUM 20                        // Max number of per block info that it can store

static size_t s_prepopulated_num = 0;
static heap_task_totals_t s_totals_arr[MAX_TASK_NUM];
static heap_task_block_t s_block_arr[MAX_BLOCK_NUM];

extern void vTaskGetRunTimeStats( char *pcWriteBuffer );
static void task_cpu(int num_arg, char** arg)
{
    char pcWriteBuffer[1024] = "";
    printf("Task\t\trun time\t%%time\n");
    vTaskGetRunTimeStats(( char *)pcWriteBuffer);
    printf("%s\n",pcWriteBuffer);
    vTaskDelay(1000 / portTICK_PERIOD_MS);
}

static void esp_dump_per_task_heap_info(int num_arg, char** arg)
{
    heap_task_info_params_t heap_info = {0};
    heap_info.caps[0] = MALLOC_CAP_8BIT;        // Gets heap with CAP_8BIT capabilities
    heap_info.mask[0] = MALLOC_CAP_8BIT;
    heap_info.caps[1] = MALLOC_CAP_32BIT;       // Gets heap info with CAP_32BIT capabilities
    heap_info.mask[1] = MALLOC_CAP_32BIT;
    heap_info.tasks = NULL;                     // Passing NULL captures heap info for all tasks
    heap_info.num_tasks = 0;
    heap_info.totals = s_totals_arr;            // Gets task wise allocation details
    heap_info.num_totals = &s_prepopulated_num;
    heap_info.max_totals = MAX_TASK_NUM;        // Maximum length of "s_totals_arr"
    heap_info.blocks = s_block_arr;             // Gets block wise allocation details. For each block, gets owner task, address and size
    heap_info.max_blocks = MAX_BLOCK_NUM;       // Maximum length of "s_block_arr"

    heap_caps_get_per_task_info(&heap_info);

    for (int i = 0 ; i < *heap_info.num_totals; i++) {
        printf("Task: %s -> CAP_8BIT: %d CAP_32BIT: %d\n",
                heap_info.totals[i].task ? pcTaskGetTaskName(heap_info.totals[i].task) : "Pre-Scheduler allocs" ,
                heap_info.totals[i].size[0],    // Heap size with CAP_8BIT capabilities
                heap_info.totals[i].size[1]);   // Heap size with CAP32_BIT capabilities
    }

    printf("\n\n");
}

static int max_retry = 5;
static int s_retry_num = 0;
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < max_retry) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init_sta(int num_arg, char** arg)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "Harshit",
            .password = "Harshit@4",
            /* Setting a password implies station will connect to all security modes including WEP/WPA.
             * However these modes are deprecated and not advisable to be used. Incase your Access point
             * doesn't support WPA2, these mode can be enabled by commenting below line */
	     .threshold.authmode = WIFI_AUTH_WPA2_PSK,

            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };
    
    strcpy((char*)wifi_config.sta.ssid, arg[1]);
    strcpy((char*)wifi_config.sta.password, arg[2]);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    /* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
     * happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to ap SSID: %s",arg[1]);
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "Failed to connect to SSID: %s", arg[1]);
    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }

    /* The event will not be processed after unregister */
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
    vEventGroupDelete(s_wifi_event_group);
}

static void help_cmd(int num_arg, char** arg)
{
    //ESP_LOGI(TAG, "HELP Command");
    for (int i=0; i<num_commands; ++i) {
        for (int j=0; j<2; ++j) {
            //ESP_LOGI(TAG, "%10s\t", commands_info[i][j]);
            printf("%10s\t", commands_info[i][j]);
        }
        printf("\n");
    }
}

static void free_heap_cmd(int num_arg, char** arg)
{
    //ESP_LOGI(TAG, "FREEHEAP Command");
    printf("Minimum free heap size : %d bytes\n",esp_get_minimum_free_heap_size());
}

static void chip_info_cmd(int num_arg, char** arg)
{
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    printf("This is %s chip with %d CPU core(s), WiFi%s%s\n",
            CONFIG_IDF_TARGET,
            chip_info.cores,
            (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
            (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");
}

static void (*command_function_pointer[10])(int num_arg, char** arg) = {help_cmd, free_heap_cmd, chip_info_cmd, esp_dump_per_task_heap_info, task_cpu, wifi_init_sta};

static void init_commands(void)
{
    commands_info[0][0] = "help";
    commands_info[0][1] = "Shows all commands";
    commands_info[1][0] = "free_heap";
    commands_info[1][1] = "Show available free heap";
    commands_info[2][0] = "chip_info";
    commands_info[2][1] = "Prints Chip Information";
    commands_info[3][0] = "task_heap_info";
    commands_info[3][1] = "Prints per task heap info";
    commands_info[4][0] = "task_cpu";
    commands_info[4][1] = "Prints per task heap info";
    commands_info[5][0] = "wifi_init";
    commands_info[5][1] = "Initialize wifi: wifi_init <ssid> <pass>";

//    command_function_pointer() = {help_cmd, free_heap_cmd};
}

static void read_console(void)
{

    bool enter_pressed = false;
    while (!enter_pressed || command_length == 0) {
        int fd;

        if ((fd = open("/dev/uart/0", O_RDWR)) == -1) {
            ESP_LOGE(TAG, "Cannot open UART");
            vTaskDelay(5000 / portTICK_PERIOD_MS);
            continue;
        }

        // We have a driver now installed so set up the read/write functions to use driver also.
        esp_vfs_dev_uart_use_driver(0);

        //char command[20];
        for (int i=0; i<50; i++) {
            command[i] = ' ';
        }
        //int index = 0;
        command_length = 0;

        while (1) {
            int s;
            fd_set rfds;
            struct timeval tv = {
                .tv_sec = 5,
                .tv_usec = 0,
            };

            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);


            s = select(fd + 1, &rfds, NULL, NULL, &tv);

            if (s < 0) {
                ESP_LOGE(TAG, "Select failed: errno %d", errno);
                break;
            } else if (s == 0) {
                ESP_LOGI(TAG, "Timeout has been reached and nothing has been received");
            } else {
                if (FD_ISSET(fd, &rfds)) {
                    char buf;
                    if (read(fd, &buf, 1) > 0) {
                        if (buf == '\n') {
                            enter_pressed = true;
                            break;
                        }
                        else if(buf == '\b')
                        {
                            if (command_length != 0) {
                                command[--command_length] = ' ';
                            }
                        }
                        else {
                            command[command_length] = buf;
                            command_length++;
                        }
                        ESP_LOGI(TAG, "Received: %s", command);
                        // Note: Only one character was read even the buffer contains more. The other characters will
                        // be read one-by-one by subsequent calls to select() which will then return immediately
                        // without timeout.
                    } else {
                        ESP_LOGE(TAG, "UART read error");
                        break;
                    }
                } else {
                    ESP_LOGE(TAG, "No FD has been set in select()");
                    break;
                }
            }
        }
        close(fd);
    }
}

static char** parse_command(int* num_arg)
{
    char** result = 0;
    
    int total_arguments = 1;

    for(int i=0; i<command_length; i++) {
        if (command[i] == ' ') {
            ++total_arguments;
        }
    }

    result = malloc(sizeof(char*) * total_arguments);

    if (result) {
        int i = 0;
        char* token = strtok(command, " ");

        while (token) {
            if(i < total_arguments) {
                *(result + i++) = strdup(token) + '\0';
                //ESP_LOGI(TAG, "%s", token);
                token = strtok(NULL, " ");
            }
        }
    }
    *num_arg = total_arguments;
    return result;

}

static void process_command()//(char** arguments, int num_arg)
{
    int num_arg = 0;
    char** arguments = parse_command(&num_arg);


    for(int i=0; i < num_commands; i++)
    {
        if (strcmp(commands_info[i][0], *(arguments + 0) ) == 0 ) {
            //ESP_LOGI(TAG, "%d %s %s", i, commands_info[i][0], *(arguments + 0));
            //ESP_LOGI(TAG, "%s", *(arguments + 1));
            command_function_pointer[i](num_arg-1, arguments);
            break;
        }
        else if (i == num_commands - 1) {
            //ESP_LOGI(TAG, "Enter valid command");
            printf("Enter valid command. Try help to see all commands\n ");
        }
    }


}

static void console_task(void* arg)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    while (1) {
        read_console();
        //int num_arg = 0;
        //char** arguments = parse_command(&num_arg);
        //process_command(arguments, num_arg);
        process_command();

        //ESP_LOGI(TAG, "READING COMPLETE!! GOING TO NEXT TASK.");
    }
}

void register_command(char* cmd, char* cmd_info, void (*func_pointer)())
{
    if (num_commands == max_commands) {
        ESP_LOGI(TAG, "Max commands reached, cannot register new command!\n");
    } else {
        commands_info[num_commands][0] = cmd;
        commands_info[num_commands][1] = cmd_info;
        command_function_pointer[num_commands] = func_pointer;
        //printf("%p", func_pointer);
        ++num_commands;
    }

}

void console_main()
{
    init_commands();
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB,
    };
    uart_driver_install(UART_NUM_0, 2*1024, 0, 0, NULL, 0);
    uart_param_config(UART_NUM_0, &uart_config);

    xTaskCreate(console_task, "console_task", 4096, NULL, 5, NULL);
}