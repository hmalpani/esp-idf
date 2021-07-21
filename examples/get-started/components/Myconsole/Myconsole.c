#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "driver/uart.h"
#include "esp_vfs.h"
#include "esp_vfs_dev.h"
#include "Myconsole.h"

static const char* TAG = "CONSOLE";

//Variable to store command entered by user and length of command
static char command[20];
static int command_length = 0;

static int num_commands = 3;
static char* commands_info[3][2];

static void help_cmd()
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

static void free_heap_cmd()
{
    //ESP_LOGI(TAG, "FREEHEAP Command");
    printf("Minimum free heap size : %d bytes\n",esp_get_minimum_free_heap_size());
}

static void chip_info_cmd(void)
{
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    printf("This is %s chip with %d CPU core(s), WiFi%s%s\n",
            CONFIG_IDF_TARGET,
            chip_info.cores,
            (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
            (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");
}

static void (*command_function_pointer[])(void) = {help_cmd, free_heap_cmd, chip_info_cmd};

static void init_commands(void)
{
    commands_info[0][0] = "help";
    commands_info[0][1] = "Shows all commands";
    commands_info[1][0] = "free_heap";
    commands_info[1][1] = "Show available free heap";
    commands_info[2][0] = "chip_info";
    commands_info[2][1] = "Prints Chip Information";

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
        for (int i=0; i<20; i++) {
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
                //ESP_LOGI(TAG, "Timeout has been reached and nothing has been received");
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
                *(result + i++) = strdup(token);
                //ESP_LOGI(TAG, "%s", token);
                token = strtok(NULL, " ");
            }
        }
    }
    *num_arg = total_arguments;
    return result;

}

static void process_command(char** arguments, int num_arg)
{
    for(int i=0; i < num_commands; i++)
    {
        if (strcmp(commands_info[i][0], *(arguments + 0) ) == 0 ) {
            //ESP_LOGI(TAG, "%d %s %s", i, commands_info[i][0], *(arguments + 0));
            command_function_pointer[i]();
            break;
        }
        else if (i == num_commands - 1) {
            //ESP_LOGI(TAG, "Enter valid command");
            printf("Enter valid command. Try help to see all commands\n ");
        }
    }


}

static void console_task(void)
{
    while (1) {
        read_console();
        int num_arg = 0;
        char** arguments = parse_command(&num_arg);
        process_command(arguments, num_arg);

        ESP_LOGI(TAG, "READING COMPLETE!! GOING TO NEXT TASK.");
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