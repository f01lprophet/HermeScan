#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/27 下午3:35
# @Author  : TT
# @File    : htmlparser.py

from matplotlib.pyplot import annotate
from front_analysise.modules.parser.baseparse import BaseParser
from front_analysise.modules.parser.jsparser import JSParser
from front_analysise.tools.comm import JSFile

import os
import re


class HTMLParser(BaseParser):

    def __init__(self, filepath):
        self._js_codes = []
        self.jsfile_citations = {}
        BaseParser.__init__(self, filepath)
        self.hidden_keywords = set()
        self.annotation_keywords = set()
        self.form_request_list = []

    def analysise(self):
        if os.path.isfile(self.fpath):
            content = ""
            self.log.debug("Start Analysise : {}".format(self.fpath))
            with open(self.fpath, "rb") as f:
                content = f.read()

            self.get_keyword(content)
            self.get_function(content)
            self.get_js_src(content)

            # 如何处理内嵌Javascript代码
            self._find_javascript_code(content)
            self.parse_jscode()

    def _find_javascript_code(self, html):
        """
        从HTML文件中寻找Javascript代码
        :param html: html代码
        :return: all 用户存放javascript代码片段的列表。
        """
        html_content = html.decode('utf-8', "ignore")
        js_codes = re.findall(r"<script>([\s\S]+?)</script>", html_content,re.I)
        js_codes = js_codes + re.findall(r"<script type=\"text/javascript\">([\s\S]+?)</script>", html_content,re.I)
        # js_codes = js_codes + re.findall(r"<script type=\"text/javascript\">([\s\S]+?)</script>", html_content,re.I)
        b_js_codes = []
        for js_code in js_codes:
            res = js_code.encode("utf-8")
            b_js_codes.append(res)
        self._js_codes = b_js_codes

    def get_keyword(self, html):
        def turn_tuple_order(data:list):
            keywords = []
            for it in data:
                keywords.append((it[1],it[0]))
            return keywords

        html_content = html.decode('utf-8', "ignore")
        name_list = re.findall(r'name="(.*?)"', html_content,re.I)
        id_list = re.findall(r'id="(.*?)"', html_content,re.I)
        results = set(name_list) | set(id_list)

        hidden_name_list = re.findall(r'type="hidden".*?name="(.*?)".*?(?:value="(.*?)"|>)', html_content, re.I) \
            + re.findall(r'name="(.*?)".*?type="hidden".*?(?:value="(.*?)"|>)', html_content,re.I) \
                + turn_tuple_order(re.findall(r'type="hidden".*?(?:value="(.*?)").*?name="(.*?)"', html_content,re.I))
        hidden_id_list = re.findall(r'type="hidden".*?id="(.*?)".*?(?:value="(.*?)"|>)', html_content,re.I) \
            + re.findall(r'id="(.*?)".*?type="hidden".*?(?:value="(.*?)"|>)', html_content,re.I) \
                + turn_tuple_order(re.findall(r'type="hidden".*?(?:value="(.*?)").*?id="(.*?)"', html_content,re.I))
        annotated_name_list = re.findall(r'<!--.*?name="(.*?)".*?(?:value="(.*?)"|>)', html_content, re.S|re.I)
        annotated_name_list2 = turn_tuple_order(re.findall(r'<!--.*?(?:value="(.*?)").*?name="(.*?)"', html_content, re.S|re.I))
        annotated_id_list = re.findall(r'<!--.*?id="(.*?)".*?(?:value="(.*?)"|>)', html_content, re.S|re.I)
        annotated_id_list2 = turn_tuple_order(re.findall(r'<!--.*?(?:value="(.*?)").*?id="(.*?)"', html_content, re.S|re.I))
        self.hidden_keywords |= set(hidden_name_list)|set(hidden_id_list)
        self.annotation_keywords |= set(annotated_name_list)|set(annotated_id_list)|\
            set(annotated_name_list2)|set(annotated_id_list2)

        form_pattern = r'<form.*?action=".*?<input.*?</form>'
        action_pattern = r'<form.*?action="(.*?)"'
        name_value_pattern = r'<input.*?name="(.*?)".*?(?:value="(.*?)"|>)'
        name_value_pattern2 = r'<input.*?(?:value="(.*?)").*?name="(.*?)"'
        id_value_pattern = r'<input.*?id="(.*?)".*?(?:value="(.*?)"|>)'
        id_value_pattern2 = r'<input.*?(?:value="(.*?)").*?id="(.*?)"'
        method_pattern = r'<form.*?method="(.*?)"'
        form_list = re.findall(form_pattern, html_content, re.S|re.I)
        for form in form_list:
            action_set = set(re.findall(action_pattern,form,re.S|re.I))
            name_value_pair_list = re.findall(name_value_pattern,form,re.S|re.I) \
                + turn_tuple_order(re.findall(name_value_pattern2,form,re.S|re.I))
            id_value_pair_list = re.findall(id_value_pattern,form,re.S|re.I) \
                + turn_tuple_order(re.findall(id_value_pattern2,form,re.S|re.I))
            method_set = set(re.findall(method_pattern,form,re.S|re.I))
            params_set = set(name_value_pair_list+id_value_pair_list)
            if len(action_set) != 0:
                params = {}
                for k,v in params_set:
                    params[k] = v
                for action in action_set:
                    req = {}
                    req['uri'] = action
                    req['params'] = params
                    if len(method_set) > 0:
                        req['methods'] = method_set
                    self.form_request_list.append(req)

        for res in results:
            self._get_keyword(res, check=0)

    def get_function(self, html):
        html_content = html.decode('utf-8', "ignore")
        path_list = re.findall(r'action="(.*?)"', html_content,re.I)
        for path in path_list:
            self._get_function(path, check=0)

    def get_js_src(self, html):
        html_content = html.decode('utf-8', 'ignore')
        src_list = re.findall(r'<script src="(.*?)"></script>', html_content,re.I)
        for src in src_list:
            res = src.find("?")
            if res > 0:
                src = src[:res]
            src_file = src.split("/")[-1]
            js_obj = self.jsfile_citations.get(src_file, JSFile(src))
            js_obj.add_depend(self.fpath)
            self.jsfile_citations.update({src_file: js_obj})

    def parse_jscode(self):
        for js in self._js_codes:
            tmp_keyword , tmp_functions= JSParser.js_in_html_parse(js)
            for key in tmp_keyword:
                self.get(key, check=1)

            for action in tmp_functions:
                self._get_function(action, check=0)

    def get_jsfile_citations(self):
        return self.jsfile_citations


if __name__ == "__main__":
    pass