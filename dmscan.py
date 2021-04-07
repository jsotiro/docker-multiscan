#!/usr/local/bin/python3
import logging
import argparse
import sys
import re
import os
from _datetime import datetime
        
import pandas as pd
import yaml
from pandas.api.types import is_numeric_dtype
from scanner_plugin import ScannerPlugin
import xlsxwriter.utility as xlsutil


def config(yaml_filename):
    scanner_config = None
    with open(yaml_filename) as file:
        scanner_config = yaml.load(file, Loader=yaml.FullLoader)
    return scanner_config


levels = {
    'critical': logging.CRITICAL,
    'error': logging.ERROR,
    'warn': logging.WARNING,
    'info': logging.INFO,
    'debug': logging.DEBUG
}
logging_level = logging.INFO
config = config('scanners.yml')
if 'logging' in config:
    if 'level' in config['logging']:
        logging_level = levels[str(config['logging']['level']).lower()]
log_format = '%(asctime)s.%(msecs)03d %(levelname)s] %(message)s'
logging.basicConfig(format=log_format, datefmt='%Y-%m-%d,%H:%M:%S', level=logging_level)

not_found_string = '-'
columns = config['columns']
severities = config['severities']
severities_summaries = severities.copy()
severities_summaries.append(not_found_string)
severity_indices = {k: v + 1 for v, k in enumerate(reversed(severities))}
severity_reverse_idx = dict([(value, key) for key, value in severity_indices.items()])

severity_mappings = config['severity-mappings']

cols = ['cve']
scanners = list(config['plugins'].keys())
cols.extend(scanners)
cves = pd.DataFrame(columns=cols)

cols = ['component']
cols.extend(scanners)
components = pd.DataFrame(columns=cols)


def calculate_composite_severity_rate(data_row):
    result = ""
    severity_rates = []
    for item in data_row:
        if type(item) != str:
            severity_rates.append(item)
    severity_rates.sort(reverse=True)
    result = result.join(map(str, severity_rates))
    return int(result)


def merge_aggregates(aggregates, aggregate_name, merge_fields=None, fill_na_value=0):
    scanners = list(aggregates.keys())
    if merge_fields is None:
        merge_fields = aggregate_name
    summary_df = pd.DataFrame()
    for name in scanners:
        df = aggregates[name]
        if type(df) is not pd.DataFrame:
            df = pd.DataFrame(df)
        df.rename(columns={aggregate_name: name}, inplace=True)
        if summary_df.empty:
            summary_df = df
        else:
            summary_df = pd.merge(summary_df, df, on=merge_fields, how="outer")
    for col in summary_df.columns:
        summary_df[col].fillna(fill_na_value, inplace=True)
        if is_numeric_dtype(summary_df[col]):
            summary_df[col] = summary_df[col].astype(int)
    return summary_df


def populate_totals(scanner, totals, scan_time, group_by_severity_results, unique_vulns, unique_cves,
                    unique_components):
    totals_row = [scanner, scan_time, unique_vulns, unique_cves, unique_components]
    for col in severities:
        if col in group_by_severity_results.index:
            totals_row.append(group_by_severity_results[col])
        else:
            totals_row.append(0)

    totals.loc[len(totals.index)] = totals_row


def slugify(value, allow_unicode=False):
    """
    adapted from https://github.com/django/django/blob/master/django/utils/text.py
    Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
    dashes to single dashes. Remove characters that aren't alphanumerics,
    underscores, or hyphens. Convert to lowercase. Also strip leading and
    trailing whitespace, dashes, and underscores.
    """
    value = str(value)
    value = value.replace(":", "_")
    value = value.replace("/", "_")
    value = re.sub(r'[^\w\s-]', '', value.lower())
    return re.sub(r'[-\s]+', '-', value).strip('-_')


def get_valid_value(series):
    result = ""
    for value in series:
        if pd.isnull(value) or value == "":
            continue
        else:
            result = value
            break
    return result


def cve_link(cve, df):
    url = ""
    hint = ""
    try:
        url = df[df.cve == '{}'.format(cve)].link.iloc[0]
        description = get_valid_value(df[df.cve == '{}'.format(cve)].description)
        components = sorted(set(df[df.cve == '{}'.format(cve)].component.to_list()))
        hint = " ".join(components) + "\n" + description
    except Exception as ex:
        logging.error(cve + str(ex))
        url = "https://www.google.com/search?q=" + cve
    return url, hint


def write_sheet(writer, ref_data, df, prefix, name, header_format, format_values, format_styles):
    worksheet_name = '{}{}'.format(prefix, name)
    df.to_excel(writer, sheet_name=worksheet_name, index=False)
    # Get the dimensions of the dataframe
    (max_row, max_col) = df.shape
    cols = df.columns
    if max_col > 0:
        worksheet = writer.sheets[worksheet_name]
        # Make the columns wider for clarity
        i = 0
        for col in cols:
            values = df[col].map(str).to_list()
            values.append(col)
            width = len(max(values, key=len))
            if width < 20:
                width = width + 2
            else:
                width = len(col) + 2
            worksheet.set_column(i, i, width)
            i += 1
        worksheet.set_row(0, None, header_format)
        # Set the autofilter
        worksheet.autofilter(0, 0, max_row, max_col - 1)
        i = 0
        for value in format_values:
            worksheet.conditional_format(0, 0, max_row, max_col - 1,
                                         {'type': 'cell',
                                          'criteria': '=',
                                          'value': '"' + value + '"',
                                          'format': format_styles[i]})
            i += 1
        if name == 'totals':
            # scan time
            # Create a new chart object.
            scan_chart = writer.book.add_chart({'type': 'bar'})
            vuln_chart = writer.book.add_chart({'type': 'column'})
            # Add a series to the chart.
            for row in range(1, max_row + 1):
                scan_chart.add_series({
                    'name': [worksheet_name, row, 0, row, 0],
                    'values': [worksheet_name, row, 1, row, 1]})

            scan_chart.set_x_axis({'name': 'seconds'})
            scan_chart.set_title({'name': 'Scan Time'})
            scan_chart.width = 700

            for col in range(5, max_col):
                vuln_chart.add_series({
                    'categories': [worksheet_name, 1, 0, max_row, 0],
                    'name': [worksheet_name, 0, col, 0, col],
                    'fill': {'color': severity_colors[col - 5]},
                    'values': [worksheet_name, 1, col, max_row, col]})
            vuln_chart.set_title({'name': 'Vulnerabilities'})
            vuln_chart.width = 700
            # Insert the chart into the worksheet.
            cell = xlsutil.xl_rowcol_to_cell(max_row + 1, 0)
            worksheet.insert_chart(cell, vuln_chart)
            cell = xlsutil.xl_rowcol_to_cell(22, 0)
            worksheet.insert_chart(cell, scan_chart)
        elif name == 'vulnerability heatmap':
            for row in range(1, max_row + 1):
                cve = df['cve'].iloc[row - 1]
                url, hint = cve_link(cve, ref_data)
                cell = xlsutil.xl_rowcol_to_cell(row, 0)
                worksheet.write_url(cell, str(url), string=cve, tip=hint)


severity_colors = ["#b85c00", "#ff420e", "#ffd428", "#579d1c", '#999999']


def save_to_excel(image_name, totals, normalised, original):
    name = slugify(image_name)
    created = datetime.now().strftime("%Y-%m-%d.%H%M%S")
    severities_format = []
    all_data = pd.DataFrame()
    for plugin in selected_plugins:
        all_data = all_data.append(normalised[plugin])

    with pd.ExcelWriter('output/{}-{}.xlsx'.format(name, created), engine='xlsxwriter') as writer:
        bold_format = writer.book.add_format({'bold': True})
        critital_format = writer.book.add_format({'bg_color': '#b85c00',
                                                  'font_color': '#1c1c1c'})
        severities_format.append(critital_format)
        high_format = writer.book.add_format({'bg_color': '#ff420e',
                                              'font_color': '#1c1c1c'})
        severities_format.append(high_format)
        medium_format = writer.book.add_format({'bg_color': '#ffd428',
                                                'font_color': '#1c1c1c'})
        severities_format.append(medium_format)
        low_format = writer.book.add_format({'bg_color': '#579d1c',
                                             'font_color': '#1c1c1c'})
        severities_format.append(low_format)
        unknown_format = writer.book.add_format({'bg_color': '#999999',
                                                 'font_color': '#1c1c1c'})
        severities_format.append(unknown_format)

        notfound_format = writer.book.add_format({'bg_color': '#dee6ef',
                                                  'font_color': '#dee6ef',
                                                  'italic': True,
                                                  'align': 'center',
                                                  'font_size': 9})
        severities_format.append(notfound_format)
        for key in totals:
            write_sheet(writer, all_data, totals[key], "", key, bold_format, severities_summaries, severities_format)
        for key in normalised:
            if not normalised[key].empty:
                write_sheet(writer, all_data, normalised[key], "normalised-", key, bold_format, severities_summaries,
                            severities_format)
        for key in original:
            if not original[key].empty:
                write_sheet(writer, None, original[key], "original-", key, bold_format, severities_summaries,
                            severities_format)


def aggregate_dataframe(aggregates, column):
    df = pd.DataFrame(aggregates)
    aggregate_name = df.columns[0]
    df.rename(columns={aggregate_name: "total"}, inplace=True)
    df.reset_index(inplace=True, level=df.index.names)
    return df


active_plugins = []
active_plugins_idx = []
selected_plugins = []


def get_active_plugins(config):
    plugins = []
    plugins_idx = []
    i = 1
    for plugin in config:
        if is_plugin_enabled(config[plugin]):
            plugins.append(plugin)
            plugins_idx.append(i)
        i += 1
    return plugins, plugins_idx


def scan(args):
    image = args.image
    verbose = args.verbose
    offline = args.offline
    results = {}
    originals = {}
    all = {}
    cve_summary = {}
    components_summary = {}
    cve_summary_by_severity = {}
    components_summary_by_severity = {}
    severity_maps = {}
    descriptions = {}
    cves = pd.DataFrame()
    components = pd.DataFrame()
    cve_totals_by_severity = pd.DataFrame()
    components_heatmap = pd.DataFrame()
    cols = ['SCANNER', 'scan time', 'vulnerabilities', 'CVEs', 'components']
    cols.extend(severities)
    totals_df = pd.DataFrame(columns=cols)
    if not os.path.exists('output'):
        os.makedirs('output')

    for plugin in selected_plugins:
        logging.info('scanning with {}'.format(plugin))
        scanner = ScannerPlugin(plugin, config['plugins'][plugin], columns, severity_mappings, verbose=verbose,
                                offline=offline)
        results[plugin], originals[plugin] = scanner.scan(image)
        logging.info('summary for {} scan by {}'.format(image, plugin))
        scan_time = scanner.scan_time()
        if results[plugin].empty:
            logging.info('No vulnerabilities found!')
            # do the zeros with an iteration of severities
            totals_df.loc[len(totals_df.index)] = [plugin, scan_time, 0, 0, 0, 0, 0, 0, 0, 0]
        else:
            # snyk seems to have a lot of duplicate rows in json results
            results[plugin].drop_duplicates(inplace=True)
            severity_totals = results[plugin].groupby('severity').severity.count()
            logging.info(severity_totals)
            unique_vulns = results[plugin].vulnerability.drop_duplicates().shape[0]
            unique_cves = results[plugin].cve.drop_duplicates().shape[0]
            unique_components = results[plugin].component.drop_duplicates().shape[0]
            populate_totals(plugin, totals_df, scan_time, severity_totals, unique_vulns, unique_cves, unique_components)

            cve_summary[plugin] = aggregate_dataframe(
                results[plugin].groupby(["cve", "cssv_v2_severity", "cssv_v3_severity"]).cve.count(), 'cve')
            components_summary[plugin] = aggregate_dataframe(
                results[plugin].groupby(["component", "cssv_v2_severity", "cssv_v3_severity"]).component.count(),
                'component')
            severity_map = pd.DataFrame()
            severity_map['cve'] = results[plugin]['cve']
            severity_map['component'] = results[plugin]['component']
            severity_map['severity'] = results[plugin]['severity']
            # severity_map['description'] = results[plugin]['description']
            severity_map['severity_index'] = severity_map.severity.map(severity_indices)

            #            severity_map_df = aggregate_dataframe(
            #               severity_map.groupby(['cve']).severity_index.max().map(severity_reverse_idx), 'cve')

            severity_map_df = aggregate_dataframe(
                severity_map.groupby(['cve']).severity_index.max(), 'cve')

            severity_maps[plugin] = severity_map_df

            # cve_summary_by_severity[plugin] = aggregate_dataframe(
            #    results[plugin].groupby(['cve', 'severity']).cve.count(), 'cve')
            # components_summary_by_severity[plugin] = aggregate_dataframe(
            #    results[plugin].groupby(['component', 'severity']).component.count(), 'component')

            severity_map_df = aggregate_dataframe(
                severity_map.groupby(['component']).severity_index.max(), 'cve')
            components_summary_by_severity[plugin] = severity_map_df

    cve_severities = merge_aggregates(severity_maps, 'total',
                                      merge_fields=['cve'], fill_na_value=0)
    components_heatmap = merge_aggregates(components_summary_by_severity, 'total',
                                          merge_fields=['component'], fill_na_value=0)

    cves = merge_aggregates(cve_summary, 'total',
                            merge_fields=['cve', 'cssv_v2_severity', 'cssv_v3_severity'])

    components = merge_aggregates(components_summary, 'total',
                                  merge_fields=['component', 'cssv_v2_severity', 'cssv_v3_severity'])
    # cve_totals_by_severity = merge_aggregates(cve_summary_by_severity, 'total', merge_fields=['cve', 'severity'])

    all['totals'] = totals_df
    all['vulnerability heatmap'] = format_severities_map(cve_severities)
    all['component heatmap'] = format_severities_map(components_heatmap)
    all['components'] = components
    all['vulnerabities'] = cves
    save_to_excel(image, all, results, originals)


## if col is vulnerability or cve
##

def format_severities_map(df):
    # df.loc[:,'severity index']=df.sum(numeric_only=True, axis=1)
    df['severity index'] = 0
    df['severity index'] = df.apply(calculate_composite_severity_rate, axis=1)
    map_name = df.columns[0]
    df.sort_values(by=['severity index', map_name], inplace=True, ascending=False)
    map_dict = severity_reverse_idx.copy()
    map_dict[0] = not_found_string
    for scanner in df.columns[1:-1]:
        df[scanner] = df[scanner].map(map_dict)
    return df


def selected_plugins(selected_str):
    result = []
    selected_idx = map(int(selected_str))


def is_plugin_enabled(param):
    result = True
    if 'enabled' in param:
        result = param['enabled']
    return result


def filter_selected(selected):
    result = []
    for i in selected:
        idx = int(i)
        if idx in active_plugins_idx:
            result.append(active_plugins[idx - 1])
        else:
            logging.warning("invalid plugin number. it will be ignored".format(i))
    return result


if __name__ == "__main__":
    # create parser
    parser = argparse.ArgumentParser()
    # Adding optional argument
    parser.add_argument("-l", "--list", action="store_true",
                        help="lists registered scanners - can only be used on its own. any other options will be ignored when -l is specified")
    parser.add_argument("-i", "--image",
                        help="The image to scan (e.g owasp/benchmark,owasp/benchmark:latest, owasp/benchmark:1)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Shows all scanner output,  shows only summary  if ommited")
    parser.add_argument("-of", "--offline", action="store_true",
                        help="don't update nvd cache severities scores, lookup and update  if ommited")
    parser.add_argument("-s", "--scanners",
                        help=" optional. scanners to include in the scan. all (default) or specific id for scanners as found in with the -l command e.g. 3,5  to use only 3rd and 5th registered scanner  in the scan")
    # parse the arguments
    args = parser.parse_args()
    if (len(sys.argv) == 1) or ((args.list is None) and (args.image is None)):
        print(
            "Missing options. you should either specify -l to list registered scanners, or -i <image> for a docker image to scan ",
            file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(1)

    active_plugins, active_plugins_idx = get_active_plugins(config['plugins'])
    if args.list:
        i = 1
        print('registered scanners')
        for plugin in config['plugins']:
            enabled = is_plugin_enabled(config['plugins'][plugin])
            print('{} {} - Enabled:{}'.format(i, plugin, enabled))
            i += 1
        sys.exit(0)
    if args.image:
        if ":" not in args.image:
            args.image += ":latest"
        selected_plugins = active_plugins
        if args.scanners:
            selected = args.scanners.split(",")
            try:
                selected_plugins = filter_selected(selected)
            except:
                logging.warning('invalid scanner options. will be ignored')
        scan(args)
