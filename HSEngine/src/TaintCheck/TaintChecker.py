
class FunctionSummary():
    def __init__(self, name, type, input_format, output_format):
        self.name = name
        self.type = type
        self.input_format = input_format
        self.output_format = output_format
        self.addr = None

class TaintEngine():
    def __init__(self, vul_type:str):
        self.vul_type = vul_type
        self.function_summaries= []

    def set_function_summary(self):
        function_in_none_out_new = ["websGetVar", "webGetVar", "j_webGetVar",
                                    "webGetVarString", "websGetVarString",
                                    "getenv", "nvram_safe_get", "cmsObj_get", "nvram_get",
                                    "cJSON_GetObject", "cJSON_GetObjectItemCaseSensitive", "nvram_get_like"]

        for func_name in function_in_none_out_new:
            self.function_summaries.append(
                FunctionSummary(name=func_name, type="source", input_format=None, output_format=['RET']))

        function_in_3_out_2 = ["webGetVarN", "websGetVarN"]
        for func_name in function_in_3_out_2:
            self.function_summaries.append(
                FunctionSummary(name=func_name, type="source", input_format=['LEN', 3], output_format=[2]))

        function_in_2_out_2_new = ["read"]
        for func_name in function_in_2_out_2_new:
            self.function_summaries.append(
            FunctionSummary(name=func_name, type="source", input_format=['LEN', 2], output_format=[1]))

        function_in_5_out_4_new = ["cgiGetValueByNameSafe"]
        for func_name in function_in_5_out_4_new:
            self.function_summaries.append(
            FunctionSummary(name=func_name, type="source", input_format=['LEN', 4], output_format=[3]))

        function_in_2_out_1 = ["modelRead"]
        for func_name in function_in_2_out_1:
            self.function_summaries.append(
            FunctionSummary(name=func_name, type="source", input_format=['LEN', 2], output_format=[1]))

        function_in_2_mul_3_out_1 = ["fread"]
        for func_name in function_in_2_mul_3_out_1:
            self.function_summaries.append(
            FunctionSummary(name=func_name, type="source", input_format=['LEN_MUL', 2, 3], output_format=[1]))

    def update_function_summary(self):

        for src_nm in self.sources_name_list:
            has_no_summary = True
            for func_sum in self.function_summaries:
                assert isinstance(func_sum, FunctionSummary)
                if src_nm in func_sum.name:
                    has_no_summary = False
                    break

            if has_no_summary == True:
                self.function_summaries.append(FunctionSummary(name=src_nm, type="source", input_format=None,
                                                               output_format=['RET']))

    def set_source_sink(self, additional_source_functions=None, additional_sink_functions=None):

        vul_type = self.vul_type

        # CWE-119
        if vul_type == "bof":

            self.sources_name_list = ["websGetVar", "j_websGetVar", "webGetVarN", "websGetVarN", "webGetVar", "webGetVarString",
                                      "websGetVarString", "read", "getenv", "fread", "getcgi", "cmsObj_get",
                                      "cJSON_GetObjectItemCaseSensitive", "cJSON_GetObject", "nvram_get_like", "nvram_get"]

            self.sinks_name_list = ["strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf", "snprintf",
                                    "memcpy", "gets", "sscanf", "cmsUtl_strcpy", "cmsUtl_strncpy", "cmsUtl_strncat"]
        # CWE-134
        elif vul_type == "fmt":
            self.sources_name_list = ["websGetVar", "j_websGetVar", "websGetVarString", "read", "getenv",
                                     "fread"]
            self.sinks_name_list = ["printf", "vprintf"]

        # CWE-78
        elif vul_type == "ci":
            self.sources_name_list = ["websGetVar", "webGetVar", "j_websGetVar", "websGetVarN", "webGetVarString", "read", "getenv",
                                     "fread", "webGetVarN", "nvram_safe_get", "cmsObj_get", "cgiGetValueByNameSafe",
                                      "cJSON_GetObjectItemCaseSensitive", "cJSON_GetObject", "nvram_get_like"]

            self.sinks_name_list = ["CsteSystem","system", "doSystemCmd", "twsystem", "doSystem", "popen", "execv",
                                    "dlopen", "FCGI_popen", "rut_doSystemAction", "unlink", "save_encrypted_data"]

        # CWE-79
        elif vul_type == "cgixss":
            self.sources_name_list = ["getenv"]
            self.sinks_name_list = ["put", "printf"]

        # CWE-89 cve-2013-5945 D-Link DIR; TEW-654TR, Trendnet
        elif vul_type == "sqltaint":
            self.sources_name_list = ["websGetVar", "j_websGetVar", "websGetVarString", "read", "getenv",
                                     "fread"]
            self.sinks_name_list = ["exec_sql", "runsql", "sqlite3_exec"]

        # CWE-319 useofhttp, CVE-2021-20168
        elif vul_type == "useofhttp":
            self.sources_name_list = ["websGetVar", "j_websGetVar", "websGetVarString", "read", "getenv",
                                     "fread", "sprintf"]
            self.sinks_name_list = ["openurl", "system"]

        # CWE-337,335: Predictable Seed in Pseudo-Random Number Generator d-link
        elif vul_type == "predictseed":
            self.sources_name_list = ["time"]
            self.sinks_name_list = ["rand", "srand"]

        # CWE-352 CSRF
        elif vul_type == "csrf":
            self.sources_name_list = ["websGetVar", "j_websGetVar", "websGetVarString", "read", "getenv",
                                     "fread"]
            self.sinks_name_list = ["system", "doSystemCmd", "twSystem", "popen", "execv"]

        # CWE-22 TaintPath
        elif vul_type == "taintpath":
            self.sources_name_list = ["websGetVar", "j_websGetVar", "websGetVarString", "read", "getenv",
                                     "fread"]
            self.sinks_name_list = ["fopen", "unlink"]

        # CWE-497 exposesystemdata
        elif vul_type == "exposesystemdata":
            self.sources_name_list = ["websGetVar", "j_websGetVar", "websGetVarString", "read", "getenv",
                                     "fread"]
            self.sinks_name_list = ["send", "sendto"]


    def add_source_functions(self, source_func_name:str):
        self.sources_name_list.append(source_func_name)

    def add_sink_functions(self, sink_func_name:str):
        self.sinks_name_list.append(sink_func_name)

    def update_source_function_addr(self, infos):
        new_function_summaries = []
        for func in self.function_summaries:
            has_addr = False
            for info in infos:
                if func.name in info:
                    func.addr = info[3].addr
                    has_addr = True
                    break

            if has_addr:
                new_function_summaries.append(func)

        self.function_summaries = new_function_summaries
