import argparse
import logging
import os
import pickle
import angr
import sys
from datetime import datetime

from HSEngine.src.HSWrapper import  HermeScanner
from HSEngine.src.TaintCheck import TaintChecker
from HSEngine.src import utils

logging.getLogger('angr').setLevel('ERROR')
logging.getLogger('angr.analyses').setLevel('ERROR')
logging.getLogger('claripy').setLevel('ERROR')
logging.getLogger('cle').setLevel('ERROR')

#logging.basicConfig(level=logging.DEBUG,
#                    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')

class ida_function_info():
    def __init__(self, func_addr = None, func_name = None, is_source_func= False):
        self.func_addr = func_addr
        self.func_name = func_name
        self.is_source_func = is_source_func

def argsparse():
    # Parse command line parameters
    parser = argparse.ArgumentParser(description="HermeScan",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-b", "--bin", required=True, metavar="/var/ac18/bin/httpd",
                       help="Input border bin")

    parser.add_argument("-p", "--preload", required=False, metavar="/True/False",
                        help="Enable preload angr project and angr CFG")

    parser.add_argument("-t", "--type", required=True, metavar="bof/ci/fmt/csrf/cgixss/sqltaint/useofhttp/taintpath/"
                                                               "exposesystemdata/predictseed",
                       help="Taint check type")

    parser.add_argument("-d", "--directory", required=True, metavar="/root/path/_ac18.extracted",
                        help="Directory of the file system after firmware decompression")

    parser.add_argument("-o", "--output", required=True, metavar="/root/output",
                        help="Folder for output results")

    parser.add_argument("-s", "--script", required=True, metavar="function_list.txt",
                        help="ida enhanced CFG script")

    args = parser.parse_args()

    if not os.path.exists(args.bin):
        logging.error("Target bin: {} not found".format(args.bin))
        sys.exit()

    taint_type = ['bof', "ci", "fmt", "useofhttp", "csrf", "sqltaint", "predictseed", "taintpath", "cgixss"]
    if args.type not in taint_type:
        logging.error("Taint strategy: {} not found".format(args.bin))
        sys.exit()

    if args.preload:
        if args.preload == "True" or args.preload == "False":
            logging.info("Valid preload.")
        else:
            logging.error("Invalid preload value {}".format(args.preload))
            sys.exit()

    if not os.path.isdir(args.directory):
        logging.error("Firmware path entered : {} not found".format(args.directory))
        sys.exit()

    if not os.path.exists(args.output):
        logging.warning("Output dictionary: {}  not found".format(args.output))
        logging.warning("Making output dictionary by default")
        os.makedirs(args.output)

    return args

def main():

    args = argsparse()
    ida_function_addrs = []
    functions_info = []

    if args.script:
        filename = args.script

        with open(filename, 'r') as function_list:
            lines = function_list.readlines()

            for line in lines:
                func_addr = line.split(' name: ')[0]
                func_name = line.split(' name: ')[1].split(' seg:')[0]
                source_func = line.split(' name: ')[1].split(' seg:')[1].split(' source_function: ')[1].strip('\n')
                is_source_func = utils.str_to_bool(source_func)
                functions_info.append(ida_function_info(func_addr=func_addr, func_name=func_name, is_source_func=is_source_func))

        for function_info in functions_info:
            ida_function_addrs.append(int(function_info.func_addr))

    if args.type and args.bin:
        taint_engine = TaintChecker.TaintEngine(vul_type=args.type)
        taint_engine.set_source_sink()
        taint_engine.set_function_summary()

        """
        Add additional source functions and update their summaries
        """
        for function_info in functions_info:
            if function_info.is_source_func == True and function_info.func_name not in taint_engine.sources_name_list:
                taint_engine.add_source_functions(function_info.func_name)

        taint_engine.update_function_summary()

        """
        Set the Logger 
        """
        scan_time = str(datetime.now().year) + str(datetime.now().month) + str(datetime.now().day) +'-'+ str(datetime.now().hour) + \
                    str(datetime.now().minute) + '-' + str(datetime.now().second)
        scan_type = args.type
        log_file_name = args.output + "\\" + scan_time + "_" + scan_type
        log_file = args.output + "\\" + scan_time + "_" + scan_type + '.log'

        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        logger = logging.getLogger("HermeScan")
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)

        logger.info("Start Analyzing.")

        """
        If the preload flag is enable, avoid to load the binary twice
        """
        if args.preload=="False":
            vuls_scanner = HermeScanner.HermeScan(bin_name=args.bin,
                                                  vul_type=taint_engine.vul_type,
                                                  ida_function_addresses=ida_function_addrs,
                                                  p_logger=logger)
        else:
            cfg_name = args.bin + "_cfg"
            project_name = args.bin + "_angr"
            bin_cfg = pickle.load(open(cfg_name, "rb"))
            project = angr.Project._load(project_name)

            vuls_scanner = HermeScanner.HermeScan(bin_name=args.bin,
                                                  vul_type=taint_engine.vul_type,
                                                  ida_function_addresses=ida_function_addrs,
                                                  project=project,
                                                  cfg=bin_cfg,
                                                  p_logger=logger)

        logger.debug(taint_engine.sinks_name_list)
        logger.debug(taint_engine.sources_name_list)


        add_sink_addrs = []
        add_source_addrs = []

        vuls_scanner.recover_symbol(functions_info)
        vuls_scanner.recover_plt(functions_info)
        vuls_scanner.bin_project.kb.functions = vuls_scanner.bin_cfg.kb.functions
        sinks_info = vuls_scanner.get_sinks_node(taint_engine.sinks_name_list, add_sink_addrs)
        sources_info = vuls_scanner.get_sources_node(taint_engine.sources_name_list, add_source_addrs)

        source_caller_func_addrs = set()
        for source in sources_info:
            source_caller_func_addrs.add(source[0])

        vuls_scanner.get_potential_paths()

        """
        Fill the address of the source function to the struct 'FunctionSummary' from the CFG node info
        """
        taint_engine.update_source_function_addr(infos=sources_info)

        """
        Used to unit test
        vuls_scanner.single_run(taint_engine.function_summaries, log_file_name)
        """

        vuls_scanner.run(taint_engine.function_summaries)
        logger.info("End Analysis")


if __name__ == "__main__":
    main()