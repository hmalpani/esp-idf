#include<stdio.h>

#include "esp_err.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"

void console_main(void);

void register_command(char* cmd, char* cmd_info, char*(*func_pointer)());

void deinit();