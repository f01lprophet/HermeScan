black_souce_function_name = ["strncmp", "strcmp", "memset", "nvram_set", "json_object_object_add", "fprintf",
                             "printf", "cprintf", "setenv"]

white_source_function_name = ["websGetVar", "j_websGetVar", "webGetVarN", "websGetVarN", "webGetVar", 
                              "webGetVarString","websGetVarString", "read", "getenv", "fread", "getcgi", 
                              "cmsObj_get", "cJSON_GetObjectItemCaseSensitive", "cJSON_GetObject", 
                              "nvram_get_like"]

STRINGS_PATH = "/usr/bin/strings"