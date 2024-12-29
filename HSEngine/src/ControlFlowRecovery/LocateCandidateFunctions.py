import idautils
import idc
import idaapi
import os
import subprocess
from ida_search import SEARCH_DOWN, SEARCH_UP
from ida_idaapi import BADADDR
from ControlFlowRecovery.utils import *
import ida_bytes

black_source_function_name = ["strncmp", "strcmp", "memset", "nvram_set", "json_object_object_add", "fprintf",
                             "printf", "cprintf", "setenv", "fputs", "unlink", "strstr", "sprintf", "snprintf",
                             "uci_set_option", "log_log", "system", "doSystemCmd", "strcasestr", "log_debug_print",
                             "memcpy", "SetValue", "syslog", 'strcpy', 'strlen']

white_source_function_name = ["websGetVar", "j_websGetVar", "webGetVarN", "websGetVarN", "webGetVar", 
                              "webGetVarString","websGetVarString", "read", "getenv", "fread", "getcgi", 
                              "cmsObj_get", "cJSON_GetObjectItemCaseSensitive", "cJSON_GetObject", 
                              "nvram_get_like"]

arm_jump_insn_ops = ['B', 'BL']
mips_jump_insn_ops = ['jalr', 'j', 'jr']
la_op_value = BADADDR

def check_strs_in_bin(all_strs:list, bin_path:str, strings_path:str)->list:
    filter_strs = []
    os_command = strings_path + " " + "-n" + " " + "4" + " " + bin_path
    process = subprocess.Popen(args=os_command, errors=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    strings_result = stdout.decode('utf-8', errors='ignore')

    for str in all_strs:
        #print(str)
        if str in strings_result:
            filter_strs.append(str)
    
    return filter_strs

def find_jump_addr_within_arch(now_addr, arch)->int:
    #insn = idc.generate_disasm_line(now_addr, 0)
    insn_operator = idc.print_insn_mnem(now_addr)
    global la_op_value

    if arch == 'ARM':
        if insn_operator in arm_jump_insn_ops:
            jump_addr = idc.get_operand_value(now_addr, 0)
        else:
            jump_addr = BADADDR
    
    elif arch == 'mipsl' or arch == 'mipsb':
        if insn_operator == 'jalr':
            jump_addr = la_op_value

        elif insn_operator == 'la':
            la_op_value = idc.get_operand_value(now_addr, 1)
            jump_addr = BADADDR
        
        elif insn_operator == 'bal':
            jump_addr = idc.get_operand_value(now_addr, 0)

        elif insn_operator == 'jal':
            jump_addr = idc.get_operand_value(now_addr, 0)

        else:
            jump_addr = BADADDR
        
    else:
        jump_addr = BADADDR
    
    #print(arch, insn_operator, len(insn_operator), hex(jump_addr))
    return jump_addr


def get_candidate_source_functions(strs_addrs:list)->list:
    
    target_function_addrs = []
    arch, bits, endian = get_program_arch()

    for str_addr in strs_addrs:
        func = idaapi.get_func(str_addr)
        global la_op_value
        la_op_value = BADADDR
        if func:
            fc = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
            for block in fc:
                b_start = block.start_ea
                b_end = block.end_ea        
                if str_addr > b_start and str_addr < b_end:
                    now_addr = str_addr
                    print("-------------------------------------------")
                    print("now_addr is {0}, basic block end addr is {1}".format(hex(now_addr), hex(b_end)))
                    while(now_addr < b_end):
                        jump_addr = find_jump_addr_within_arch(now_addr, arch)

                        if jump_addr != BADADDR:
                            target_function_addrs.append(jump_addr)
                            break

                        now_addr = idc.next_head(now_addr)
                    break
        
    return target_function_addrs

def Get_Valid_Segment():
    Valid_Segments = []
    
    Valid_Segments_Name = ['LOAD', '.text']
    for seg in idautils.Segments():
        Segments_Scope = []
        if idc.get_segm_name(seg) in Valid_Segments_Name:
            Segments_Scope.append(seg)
            Segments_Scope.append(idc.get_segm_end(seg))
            Valid_Segments.append(Segments_Scope)
    return Valid_Segments

def get_strs_refs_addrs(filter_strs)->list:

    min_addr, max_addr = get_min_max_addr()
    all_strs_refs_addrs = []
    for single_str in filter_strs:
        #print("Now is ", single_str)
        str_refs_in_code_addrs = srch_str_addr_in_seg(single_str, min_addr, max_addr)
        for str_refs_in_code_addr in str_refs_in_code_addrs:
            all_strs_refs_addrs.append(str_refs_in_code_addr)
    
    return all_strs_refs_addrs

def save_strs_refs_addrs(saved_addrs, log_file_name):
    with open(log_file_name, "w+") as log_file:
        for addr in saved_addrs:
            log_file.write(hex(addr))
            log_file.write("\n")

def Read_Strs_Refs_Addrs_From_File(log_file_name):
    valid_addrs = []
    with open(log_file_name, 'r+') as log_file:
        addrs =log_file.readlines()
        for addr in addrs:
            valid_addr = addr.strip("\n")
            valid_addrs.append(int(addr, 16))
    return valid_addrs

def srch_str_addr_in_seg(now_str:str, start_addr, end_addr)->list:
    cur_addr = start_addr
    str_used_in_code_addrs = []

    print("now string is", now_str)
    hex_str = str.encode(now_str).hex()
    #print("now hex string is", h)
    pattern = "".join([content + " " if index % 2 else content for index, content in enumerate(hex_str)])

    while cur_addr < end_addr:
        cur_addr = idc.find_binary(cur_addr, SEARCH_DOWN, pattern, radix=16, from_bc695=False)

        if cur_addr == BADADDR:
            continue
        else:
            addr_flag = idc.get_full_flags(cur_addr)
            if idc.is_code(addr_flag):
                print("find in ", hex(cur_addr))
                if cur_addr not in str_used_in_code_addrs:
                    str_used_in_code_addrs.append(cur_addr) 
                else:
                    break
            else:
                data_refs_cur_addrs = idautils.DataRefsTo(cur_addr)
                for addr in data_refs_cur_addrs:
                    print(hex(addr))
                    if addr not in str_used_in_code_addrs:
                        str_used_in_code_addrs.append(addr) 

        cur_addr =idc.next_head(cur_addr)

    """
    ### Searching by the text, duplicating
    while cur_addr < end_addr:
        cur_addr = idc.find_text(cur_addr, SEARCH_DOWN, 0xD7790, 0, str)
        if cur_addr == BADADDR:
            continue
        else:
            addr_flag = idc.get_full_flags(cur_addr)
            if idc.is_code(addr_flag):
                print("find in ", hex(cur_addr))
                if cur_addr not in str_used_in_code_addrs:
                    str_used_in_code_addrs.append(cur_addr) 
                else:
                    break

        cur_addr =idc.next_head(cur_addr)
    """
    return str_used_in_code_addrs

def get_matching_strings_addrs(orgin_strs:str, file_path:str, strings_path:str)->list:
    #orgin_strs = "wl_rateset vpn_crt_client1_crt wrs_cc_enable wl_closed filter_lw_date_x_Tue ipv61_prefix wrs_rulelist ipv61_prefix_length onboardinglist vpn_server_reneg wl'+i+'_bsd_sta_select_policy_vht_s time_setting fb_attach_wlanlog w_apply usbclient_ip /tmp/settings attach_modemlog pptp_connected_info vpn_crt_client3_ca new_account filter_lw_time2_x_endmin wl_ampdu_rts start_update /tmp/notify/usb/sambaclient wps_band_tr wl_dtim filter_lwlist_Block dhcpEnable vpn_server_nm fb_pdesc wl1_bsd_steering_phy_g ipv6_dns2 vpn_crt_server1_static label_create_account fw_enable_x dhcp_static vpnc_clientlist ipv6_prefix_len_wan ipv6_ipaddr_r vpn_crt_client5_key /tmp/smartsync/dropbox TM_EULA remove_passwd vpn_server_clientlist_username wrs_vp_enable wl2_bw ipsec_profile_client_2_ext attach_cfgfile_id edit_vpn_crt_server1_dh ipv6_dnsenable permission ipsec_profile_1 vpn_server_poll url_enable_x wl_radius_port mr_enable_x tr_wan_unit ipv61_dnsenable fb_email ipv6_prefix_length_r ipv61_dhcp_pd wl1_bsd_steering_policy wans_ntool_unit wl_expire ipsec_dpd pptpd_clients wl_country_code wans_lb_ratio_1 vpn_crt_server1_key modem_pincode ipv61_prefix_r qos_obw voip_port sig_update wl0_11ax vpn_crt_client5_crt emf_enable fb_email_provider vpn_serverx_dns qos_type_tr ddns_return_code_chk wl_radius_ipaddr vpn_upload_type vpn_server_local ipv6_dhcp_pd vpn_crt_client1_crl vpn_crt_client4_ca wl_expire_day wans_primary new_re_mac ipsec_dead_peer_detection_en wl1_macmode vpn_server_hmac vpn_crt_client3_crt wl1_bw bridge_port filter_lw_time_x secondary_line action_wait vpn_server_c2c ttl_inc_enable wl_bss_enabled_field edit_vpn_crt_client_static GWStatic vpn_crt_client3_crl bwdpi_wh_enable cloud_username sshd_enable_tr filter_lw_date_x_Thu iptv_port4 layer_order wps_enable_word wrs_mals_enable sig_update_date sshd_authkeys /tmp/smartsync/usbclient/config sambaclient_name wl_bw fw_lw_enable_x filter_lw_time_x_endmin MULTIFILTER_MAC wl2_bsd_steering_policy vpn_crt_client4_static webs_update_trigger ipv61_dhcp_end fb_attach_cfgfile vpn_crt_server1_crl iptv_port iptv_stb_port ipsec_server_enable vpn_server_crypt switch_wan1prio bsd_if_select_div /tmp/smartsync/dropbox/temp/ autofw_rulelist switch_wan1tagid filter_lw_date_x_Sun vpn_crt_client1_key apps_flag MULTIFILTER_ENABLE attach_modemlog_id wans_mode_tr vpn_crt_client2_crl edit_vpn_crt_server1_crl filter_lw_icmp_x bwdpi_app_rulelist_edit filter_lw_date_x_Wed ipsec_client_list_1 PM_MY_EMAIL_TMP wan_dhcpenable_x wan_vpndhcp ipv61_rtr_addr switch_wan3prio vpn_server_x_dns wgsc_enable wl_mode_x wlc_express qos_ibw1 edit_vpn_crt_server1_crt wps_method dhcp_enable_x action_script wl2_macmode iTunes sambaclient_ip ipsec_client_list_Block wl0_macmode secondary_wan_line mon_day vpn_serverx_eas wl_wpa_psk_org sim_pincode partition_div wandog_interval wandog_enable_chk custom_clientlist ipsec_client_list_table st_ftp_mode wl_11ax vpn_server_r2 game_vts_rulelist ipv6_6rd_prefix MULTIFILTER_MACFILTER_DAYTIME qos_rulelist switch_wan2tagid tr_wans_primary host_name_tr vpn_crt_client1_static vpn_server_if diskmon_usbport wl_bw_enabled edit_vpn_crt_server1_key vpn_server_ccd ipv6_service wan10_ipaddr_x wans_lb_ratio filter_lw_date_x_Mon fb_fail_content wrs_protect_enable ctf_fa_mode speedTest_history_div ipv6_prefix_span yadns_mode bwdpi_db_enable new_folder switch_wan3tagid wl0_country_code PM_SMTP_AUTH_USER webdav_proxy edit_vpn_crt_server1_static /tmp/smartsync/dropbox/script /replies_tree/0/dnssec_status /tmp/smartsync/usbclient/script/write_nvram wl_maclist_x reboot_schedule_enable_tr /tmp/smartsync/sambaclient/script ipv6_prefix_s secondary_wan_icon ipv61_service edit_vpn_crt_client_ca wl1_bsd_steering_policy_x label_account_list btn_create_account fb_desc0 sshd_pass ob_path wl2_bsd_steering_phy_g fb_serviceno filter_lw_date_x_Fri wl0_bsd_steering_policy shell_timeout_x switch_wan0tagid edit_vpn_crt_client_crt wl0_maclist_x wan1_routing_isp_enable machine_name PM_SMTP_AUTH_USER_TMP filter_lw_date_x_Sat slave_mac ipv6_prefix_length_span IPsetting /var/spool switch_stb_x ipv61_tun_addr wl_subunit wrs_enable_ori vpn_crt_client2_crt apps_analysis /tmp/smartsync/usbclient/script usericon_mac apps_state_desc fb_comment wl_bw_dl attach_cfgfile wl1_bsd_steering_phy_l ipsec_profile_client_1 usb_usb3 ipsec_profile_client_2 filter_lwlist2 wl0_bsd_steering_phy_l desc_create_account wl_user_rssi ddns_status /tmp/smartsync/usbclient wrs_app_enable qos_ibw wl_phrase_x modem_apn SystemCmd vpn_crt_client3_static reboot_schedule wl'+i+'_bsd_sta_select_policy_rssi qos_enable cert_status /var/spool/cron/crontabs /tmp/smartsync/sambaclient/config modem_isp le_crypt fb_ptype ipv6_prefix_length_s smart_connect_switch ipv61_prefix_length_r tr_permission ipv6_ipaddr_span wl_sync_node wl_bw_dl_x ipsec_dead_peer_detection attach_wlanlog vpn_server_rgw /tmp/smartsync/sambaclient wrs_service selected_account wl_mbss filter_lw_time2_x_endhour lacp_enabled custom_usericon iptv_port_settings vpn_crt_client5_ca wan0_enable wan0_routing_isp_enable manualCa wl_txbf table_account_list lock_selection MULTIFILTER_DEVICENAME wl_unit logined_ip_str wl_bw_ul_x disk_model_name PM_MY_EMAIL wans_dualwan ipv61_prefix_length_s schedule_date edit_vpn_crt_client_crl ipv6_dhcp_end wl_timesched fb_email_provider_field tr_adv_dead_peer_detection wl_radius_key wps_band vpn_server_pdns ipv61_prefix_length_span diskmon_part vpn_crt_client5_static ipsec_profilename remove_passwd_field url_rulelist MULTIFILTER_MACFILTER_DAYTIME_V2 bsd_bounce_detect_x vpn_server_r1 sig_update_scan wlX_rast_static_client ipsec_local_public_interface vpn_server_proto ipsec_profile_item /tmp/smartsync/sambaclient/script/write_nvram wl2_maclist_x save_icon dblog_transid ipv6_prefix_length edit_vpn_crt_client_key wps_enable_hint wan_gateway_x_now vpn_server_x_eas ipv6_prefix ipv61_6rd_prefix new_profile_name wl_ofdma bsd_bounce_detect bwdpi_app_rulelist wl2_bsd_steering_policy_x ipv6_dns1 pin_apply login_captcha sim_puk login_authorization vpn_crt_client4_crl fb_attach_syslog vpn_server_sn upload_unit wl0_bsd_steering_phy_g fb_attach_modemlog group_id custom_usericon_del filter_lw_default_x switch_stb_x0 qos_obw1 dhcp_static_x wans_routing_enable /tmp/smartsync/dropbox/cert vpn_client_unit vpn_crt_server1_dh autofw_enable_x telnetd_enable wl_lanaccess sitesurvey_tr ipv6_rtr_addr body wollist vpn_server_dhcp attach_syslog_id wl_expire_hr ipv6_prefix_r edit_vpn_crt_server1_ca vpn_crt_client2_key wl_rts share_link_param wl0_bw wl2_bsd_steering_phy_l /tmp/smartsync/dropbox/temp ipv6_ipaddr lan_gateway attach_syslog ftp_port wandog_enable xlease ipv6_tun_addr wl'+i+'_bsd_if_qualify_policy_vht_s wandog_maxfail switch_wan2prio captcha_enable time_zone_dstoff vpn_crt_client1_ca switch_wan0prio client_image vpn_crt_server1_ca ipv6_rtr_addr_s current_page http_clientlist login_captcha_tr udpxy_enable_x voip_port3 dummyShareway vpn_server_port_basic vpn_crt_server1_crt vpn_clientx_eas time_zone_select http_autologout /tmp/smartsync/dropbox/config wl_rf_enable vts_enable_x import_cert_file port_settings bwdpi_game_list vpn_crt_client5_crl enable_mac amas_release_note vpn_server_plan ipsec_profile_2 qos_bw_rulelist pptpd_clientlist_Block xnetmask wans_mode_fo wans_lb_ratio_0 vpn_crt_client3_key wl_expire_min ipv61_prefix_s apps_action vpn_server_comp wrs_app_rulelist fb_browserInfo isp_profile_tr wl_bw_ul wl_maclist_x_0 vpn_crt_client4_key next_page /tmp/smartsync/dropbox/temp/swap ipsec_client_list_ike mail_provider ipsec_client_list_2 wl_mbo_enable /tmp/notify/usb/usbclient ipsec_profile_client_1_ext action_mode filter_lwlist_table vlan_rulelist filter_lw_time2_x bw_enabled_x wireless_encryption ipv61_rtr_addr_s upnp_icon wl_itxbf vpn_server_port_adv vpn_server_clientlist_password wl_mfp vpn_crt_client2_static Dropbox vpn_server_port sr_rulelist reboot_schedule_enable MULTIFILTER_ALL vpn_crt_client4_crt filter_lwlist PM_SMTP_AUTH_PASS vts_rulelist /var/spool/cron wl_atf filter_lw_date_x ipv6_dns3 vpn_crt_client2_ca ipv61_ipaddr_r shell_timeout vpn_server_unit pool wl_rast_static_client_Block switch_wantag vpn_serverx_clientlist apps_name st_ftp_force_mode wps_sta_pin iptv_ipaddr wan1_enable share_link_host wan_netmask_x_now upnp_service vts_ftpport vpn_upload_unit pptpd_clientlist_table user_type sharelink dhcp_lease radio_VPNServer_enable wan11_ipaddr_x wl1_maclist_x VPNServer_enable attach_wlanlog_id wl_igs wan_enable fb_desc1 reboot_schedule_enable_x ipv61_ipaddr"
    split_strs = orgin_strs.split(" ")
    file_name = file_path.split("\\")[-1]
    log_file_name = file_name + "_para_results.txt"

    filter_strs = check_strs_in_bin(split_strs, file_path, strings_path)
    #filter_strs = ["wrs_rulelist"]
    print("filter_strs is",filter_strs)
    print("filter str number is {0}, orgin str number is {1}".format(len(filter_strs), len(split_strs)))
    strs_ref_addrs = get_strs_refs_addrs(filter_strs)
    save_strs_refs_addrs(strs_ref_addrs, log_file_name)

    return strs_ref_addrs

def filter_source_functions_with_name(source_functions_frequency:list)->list:
    filter_source_functions = []
    # element= (func_addr, frequency)
    for element in source_functions_frequency:
        func_name = idc.get_func_name(element[0])
        if func_name in white_source_function_name:
            filter_source_functions.append(element[0])
            continue

        if func_name in black_source_function_name:
            continue

        if element[1] <= 2:
            continue

        filter_source_functions.append(element[0])
    
    for func_start_addr in idautils.Functions():
        func_name = idc.get_func_name(func_start_addr)
        if func_name in white_source_function_name:
            filter_source_functions.append(func_start_addr)

    print(filter_source_functions)
    
    return filter_source_functions


def get_source_functions(*args, **kwargs)->list:
    strs_addrs_list:list = kwargs.get("strs_addrs_list", [])
    strs_addrs_file = kwargs.get("strs_addrs_file", "")

    if len(strs_addrs_list)!=0:
        strs = strs_addrs_list
    
    if strs_addrs_file!="":
        strs = Read_Strs_Refs_Addrs_From_File(strs_addrs_file)
    
    candidate_source_functions  = get_candidate_source_functions(strs)
    candidate_source_functions_dict = {}
    for key in candidate_source_functions:
        candidate_source_functions_dict[key] = candidate_source_functions_dict.get(key, 0) + 1
    
    source_function_frequency = sorted(candidate_source_functions_dict.items(),key=lambda x:x[1], reverse=True)
    print("Candidate source functions with frequency are:\n")
    print(source_function_frequency)

    return filter_source_functions_with_name(source_function_frequency)

def read_orgin_strs(file_path):
    orgin_strs_file = file_path + '_origin_strs.txt'
    with open(orgin_strs_file, "r+") as org_str_file:
        org_strs = org_str_file.read()
        return org_strs

def my_run(strings_path:str):
    now_file_name = get_file_name()
    now_file_path = get_file_path()
    org_strs = read_orgin_strs(now_file_path)
    #print(org_strs)
    
    if org_strs != "":
        strs_addrs = get_matching_strings_addrs(org_strs, now_file_path, strings_path)
        source_functions_list = get_source_functions(strs_addrs_list=strs_addrs)

        return source_functions_list




