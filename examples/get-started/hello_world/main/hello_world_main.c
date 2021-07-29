/* Hello World Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "Myconsole.h"

void hello(int num_arg, char** arg)
{
    if(num_arg == 0)
    {
        printf("Missing arguments");
        //return;
    } else {
    printf("HELLO %s from this function\n",arg[1]);
    return;
    }
}

void app_main(void)
{
    printf("Hello world!\n");
    register_command("hello", "test command", hello);
    console_main();
}
