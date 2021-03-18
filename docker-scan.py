#!/bin/python
import logging
import argparse
import re
from _datetime import datetime

import pandas as pd
import yaml
from pandas.api.types import is_numeric_dtype
from scanner_plugin import ScannerPlugin


log_format = '%(asctime)s.%(msecs)03d %(levelname)s] %(message)s'
logging.basicConfig(format=log_format, datefmt='%Y-%m-%d,%H:%M:%S', level=logging.DEBUG)



def config(yaml_filename):
    scanner_config = None
    with open(yaml_filename) as file:
        scanner_config = yaml.load(file, Loader=yaml.FullLoader)
    return scanner_config


config = config('scanners.yml')
columns = config['columns']
severities = config['severities']
severity_mappings = config['severity-mappings']

cols = ['cve']
scanners = list(config['plugins'].keys())
cols.extend(scanners)
cves = pd.DataFrame(columns=cols)

cols = ['component']
cols.extend(scanners)
components = pd.DataFrame(columns=cols)


def merge_aggregates(aggregates, aggregate_name, merge_fields=None):
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
        summary_df[col].fillna(0, inplace=True)
        if is_numeric_dtype(summary_df[col]):
            summary_df[col] = summary_df[col].astype(int)
    return summary_df


def populate_totals(scanner, totals, group_by_severity_results, unique_vulns, unique_cves, unique_components):
    totals_row = [scanner, unique_vulns, unique_cves, unique_components]
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


def save_to_excel(image_name, normalised, original):
    name = slugify(image_name)
    created = datetime.now().strftime("%Y-%m-%d.%H%M%S")
    with pd.ExcelWriter('output/{}-{}.xlsx'.format(name, created)) as writer:
        for key in normalised:
            if key in scanners:
                prefix = "normalised-"
            else:
                prefix = ""
            normalised[key].to_excel(writer, sheet_name='{}{}'.format(prefix, key))
        for key in original:
            original[key].to_excel(writer, sheet_name='original-{}'.format(key))


def aggregate_datafarame(aggregates, column):
    df = pd.DataFrame(aggregates)
    aggregate_name = df.columns[0]
    df.rename(columns={aggregate_name: "total"}, inplace=True)
    df.reset_index(inplace=True, level=df.index.names)
    return df


def scan(image, verbose):
    results = {}
    originals = {}
    cve_summary = {}
    components_summary = {}
    cve_summary_by_severity = {}
    components_summary_by_severity = {}
    cves = pd.DataFrame()
    components = pd.DataFrame()
    cve_totals_by_severity = pd.DataFrame()
    components_totals_by_severity = pd.DataFrame()
    cols = ['SCANNER', 'unique_vulnerabilities', 'unique_CVEs', 'unique_components_scanned']
    cols.extend(severities)
    totals_df = pd.DataFrame(columns=cols)
    for plugin in config['plugins']:
        logging.info('scanning with {}'.format(plugin))
        scanner = ScannerPlugin(plugin, config['plugins'][plugin], columns, severity_mappings, verbose=verbose)
        results[plugin], originals[plugin] = scanner.scan(image)
        logging.info('summary for {} scan by {}'.format(image, plugin))
        if results[plugin].empty:
            logging.info('No vulnerabilities found!')
            totals_df.loc[len(totals_df.index)] = [plugin, 0, 0, 0, 0, 0, 0, 0]
        else:
            # snyk seems to have a lot of duplicate rows in json results
            results[plugin].drop_duplicates(inplace=True)
            severity_totals = results[plugin].groupby('severity').severity.count()
            logging.info(severity_totals)
            unique_vulns = \
                results[plugin].vulnerability.drop_duplicates().shape[0]
            unique_cves = results[plugin].cve.drop_duplicates().shape[0]
            unique_components = results[plugin].component.drop_duplicates().shape[0]
            populate_totals(plugin, totals_df, severity_totals, unique_vulns, unique_cves, unique_components)

            cve_summary[plugin] = aggregate_datafarame(
                results[plugin].groupby(["cve", "cssv_v2_severity", "cssv_v3_severity"]).cve.count(), 'cve')
            components_summary[plugin] = aggregate_datafarame(
                results[plugin].groupby(["component", "cssv_v2_severity", "cssv_v3_severity"]).component.count(),
                'component')

            cve_summary_by_severity[plugin] = aggregate_datafarame(
                results[plugin].groupby(['cve', 'severity']).cve.count(), 'cve')
            components_summary_by_severity[plugin] = aggregate_datafarame(
                results[plugin].groupby(['component', 'severity']).component.count(), 'component')

            cves = merge_aggregates(cve_summary, 'total',
                                    merge_fields=['cve', 'cssv_v2_severity', 'cssv_v3_severity'])

            components = merge_aggregates(components_summary, 'total',
                                          merge_fields=['component', 'cssv_v2_severity', 'cssv_v3_severity'])

    cve_totals_by_severity = merge_aggregates(cve_summary_by_severity, 'total', merge_fields=['cve', 'severity'])
    components_totals_by_severity = merge_aggregates(components_summary_by_severity, 'total',
                                                     merge_fields=['component', 'severity'])

    results['totals'] = totals_df
    results['cve-summary'] = cves
    results['components-summary'] = components
    results['cve-severity-summary'] = cve_totals_by_severity
    results['components-severity-summary'] = components_totals_by_severity
    save_to_excel(image, results, originals)


if __name__ == "__main__":
    # create parser
    parser = argparse.ArgumentParser()
    # Adding optional argument
    parser.add_argument("-i", "--image", help="The image to scan (e.g owasp/benchmark,owasp/benchmark:latest, owasp/benchmark:1) ", required=True)
    parser.add_argument("-v", "--verbose", help="True shows all scanner output, False (default) shows only summary ")
    # parse the arguments
    args = parser.parse_args()
    if args.image:
        if ":" not in args.image:
            args.image +=":latest"
        verbose = args.verbose is not None
        scan(args.image,verbose)
