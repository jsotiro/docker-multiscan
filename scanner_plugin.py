import json
import os
import re
import subprocess
import datetime
import pandas as pd
import requests
from nvd_cache import NvdCache
import logging


def safe_get_key(dict, key):
    if key in dict:
        return dict[key]
    else:
        return None


cves_dict = {}


class ScannerPlugin:
    def __init__(self, plugin, plugin_config, columns, severity_mappings, verbose=False, offline=False):
        self.name = plugin
        self.config = plugin_config
        self.command_line = plugin_config['command_line']
        self.resultsRoot = plugin_config['results_root']
        self.columnMappings = plugin_config['mappings']
        self.output_file = safe_get_key(plugin_config, 'output_file')
        self.flatten_key_value_pairs = safe_get_key(plugin_config, 'flatten_key_value_pairs')
        self.severity_mappings = severity_mappings
        self.columns = columns
        self.cve_cache = NvdCache()
        self.timeout_in_secs = 60
        self.timeout_in_secs = 60
        self.started = None
        self.finished = None
        self.failed = False
        self.verbose = verbose
        self.offline = offline

    def scan_time(self):
        scan_time = (self.finished - self.started).total_seconds()
        return scan_time

    def scan_image(self, command_line_params):
        scanner = subprocess.Popen(command_line_params, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.started = datetime.datetime.now()
        stdout, stderr = scanner.communicate()
        stdout = stdout.decode('utf-8')
        stderr = stderr.decode('utf-8')
        if self.verbose:
            logging.info(stdout)
            logging.error(stderr)
        if self.output_file:
            start = datetime.datetime.now()
            elapsed_secs = 0
            while not os.path.isfile(self.output_file) and elapsed_secs <= self.timeout_in_secs:
                now = datetime.datetime.now()
                elapsed_secs = (now - start).total_seconds()
            self.failed = elapsed_secs > self.timeout_in_secs
            if not self.failed:
                json_file = open(self.output_file, )
                json_result = json.load(json_file)
                os.remove(self.output_file)
            else:
                json_result = {"error": "waiting for results file timed-out"}
        else:
            if stderr != "":
                json_result = {"error": stderr}
            else:
                json_result = json.loads(stdout)
        self.finished = datetime.datetime.now()
        return json_result

    def flatten_list_to_first_item(self, item):
        if type(item) is list:
            if len(item) > 0:
                return str(item[0])
            else:
                return ""
        else:
            return item

    def cve_from_reference(self, vuld_id, url):
        cve = vuld_id
        try:
            html = requests.get(url).content
            result = re.search("CVE-\d{4}-\d*", str(html), flags=re.IGNORECASE)
            if result:
                cve = result[0]
        except Exception as e:
            msg = "error in retrieving cve from link " + str(e)
            logging.error(msg)
            cve = vuld_id
        return cve

    def cvss_severities(self, cve):
        cssv_v2 = ""
        cssv_v3 = ""
        try:
            cve_details = self.cve_cache.get_item(cve, offline=self.offline)
            if "result" in  cve_details:
                if "CVE_Items" in  cve_details["result"]:
                    if "impact" in  cve_details["result"]["CVE_Items"][0]:
                        if "baseMetricV2" in cve_details["result"]["CVE_Items"][0]["impact"]:
                            cssv_v2 = cve_details["result"]["CVE_Items"][0]["impact"]["baseMetricV2"]["severity"]
                        if "baseMetricV3" in cve_details["result"]["CVE_Items"][0]["impact"]:
                            cssv_v3 = cve_details["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
        except Exception as ex:
            msg = cve + str(ex)
            logging.error(msg)
        return cssv_v2, cssv_v3

    def replace_GSHA_withCVE(self, item):
        if item.vulnerability.startswith('CVE') or pd.isna(item.link):
            item['cve'] = item.vulnerability
        else:
            item['cve'] = self.cve_from_reference(item.vulnerability, item.link)
        cssv_v2 = ""
        cssv_v3 = ""
        if str(item['cve']).lower().startswith("cve"):
            cssv_v2, cssv_v3 = self.cvss_severities(item['cve'])
        item['cssv_v2_severity'] = cssv_v2
        item['cssv_v3_severity'] = cssv_v3

        return item

    def normalize_results(self, df):
        if self.columnMappings:
            df.rename(columns=self.columnMappings, inplace=True)
        for col in df.columns:
            if col not in self.columns:
                df.drop([col], axis='columns', inplace=True)
            else:
                df[col] = df[col].map(self.flatten_list_to_first_item, na_action='ignore')

        # df['vulnerability'] = df['vulnerability'].map(self.flatten_list_to_first_item, na_action='ignore')

        df['cve'] = df['vulnerability']

        # df['link'] = df['link'].map(self.flatten_list_to_first_item, na_action='ignore')
        df['severity'] = df['severity'].str.upper()
        df['severity'] = df['severity'].map(self.severity_mappings)
        df['cssv_v2_severity'] = df['severity']
        df['cssv_v3_severity'] = df['severity']

        df = df.apply(self.replace_GSHA_withCVE, axis=1)
        return df

    def parsed_image_name(self, full_image_name):
        name = ""
        author = ""
        tag = ""
        if ":" in full_image_name:
            temp = full_image_name.split(":")
            main = temp[0]
            tag = temp[1]
        else:
            tag = "latest"
            main = full_image_name
        if "/" in main:
            temp_name = main.split("/")
            author = temp_name[0]
            name = temp_name[1]
        else:
            name = main
        return author, name, tag

    '''
    secure version of eval to allow the dynamic evaluation of filenames 
    but nothing else
    '''

    def eval_expression(self, input_string, image_author, image_name, image_tag):
        allowed_names = {"format": format, "image_author": image_author,
                         "image_name": image_name,
                         "image_tag": image_tag}
        code = compile(input_string, "<string>", "eval")
        for name in code.co_names:
            if name not in allowed_names:
                raise NameError(f"Use of {name} not allowed")
        return eval(code, {"__builtins__"   : {}}, allowed_names)

    def transpose_key_value_pairs_to_named_keys(self, json, root, pair_parent, key_name, value_name):
        json_array = json[root]
        for element in json_array:
            for attribute in element[pair_parent]:
                element[attribute[key_name]] = attribute[value_name]

    def unpack_json_values(self, json, root, json_parent):
        json_array = json[root]
        for element in json_array:
            i = 0
            for node in element[json_parent]:
                for key in node.keys():
                    name = json_parent + "." + key
                    if i > 0:
                        name = name + "_" + str(i)
                    element[name] = node[key]
                i += 1

    '''
    happens before we transform the json results to a dataframe 
    and helps with flattening json into tabular form
    '''

    def pre_process_json(self, json_results):
        if self.flatten_key_value_pairs:
            self.transpose_key_value_pairs_to_named_keys(
                json_results,
                self.resultsRoot,
                self.flatten_key_value_pairs['below'],
                self.flatten_key_value_pairs['key_name'],
                self.flatten_key_value_pairs['value_name'])
        if 'unpack_json' in self.config:
            for item in self.config['unpack_json']:
                self.unpack_json_values(json_results, self.resultsRoot, item)

    '''
    we transform the json report to a dataframe 
    and consolidate columns and values so that all 
    scanner results have the same reference names 
    '''

    def preprocess_dataframe(self, json_results):
        try:
            results = pd.json_normalize(json_results, record_path=self.resultsRoot)
        except KeyError as e:
            json_subtree = json_results[0][self.resultsRoot]
            results = pd.json_normalize(json_subtree)
        original = results.copy()
        if not results.empty:
            self.normalize_results(results)
        return results, original

    def scan(self, image):
        results = pd.DataFrame()
        original = pd.DataFrame()
        cmd = self.command_line
        cmd.append(image)
        image_author, image_name, image_tag = self.parsed_image_name(image)
        if self.output_file:
            self.output_file = self.eval_expression(self.output_file, image_author, image_name, image_tag)
        json_results = self.scan_image(cmd)
        if not "error" in json_results:
            self.pre_process_json(json_results)
            results, original = self.preprocess_dataframe(json_results)
        return results, original
