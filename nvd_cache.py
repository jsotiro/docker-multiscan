import json

import requests
from sqlalchemy import create_engine
import pandas as  pd
import logging
import utils
from datetime import datetime, timedelta


class NvdCache:
    __instance = None

    @staticmethod
    def get_instance():
        if NvdCache.__instance is None:
            __instance = NvdCache()
        return NvdCache.__instance

    def __init__(self):
        self.dbname = 'nvd-cache.db'
        self.engine = create_engine('sqlite:///' + self.dbname, echo=False)
        self.sqlite_connection = self.engine.raw_connection()
        self.sqlite_table = "vulnerabilities"
        self.cache_ttl = timedelta(days=30)
        self.items_found_max = 20
        self.items_found = 1

        if self.table_exists():
            sql = "select * from {}".format(self.sqlite_table)
            self.df = pd.read_sql(sql, self.sqlite_connection, index_col='cve', parse_dates='last_updated')
        else:
            self.df = pd.DataFrame(columns={'details', 'last_updated'})

    def read_cve_list(self, filename):
        self.df = pd.read_csv('cves-list.txt', header=None, names=['cve'])
        self.df.drop_duplicates(inplace=True)
        self.df['details'] = ''
        self.df['last_updated'] = pd.Timestamp.min
        self.df.set_index('cve', inplace=True)

    def create_from_list(self):
        if not self.table_exists():
            self.df = self.df.apply(self.import_df_entry, axis=1)
            self.df.to_sql(self.sqlite_table, self.sqlite_connection)

    def create_for_cve_list(self, filename):
        self.read_cve_list(filename)
        self.create_from_list()

    def has_expired(self, timestamp):
        now = datetime.now()
        return timestamp < now - self.cache_ttl

    def get_updated_entry(self, cve):
        url = "https://services.nvd.nist.gov/rest/json/cve/1.0/{}".format(cve)
        try:
            json_response = requests.get(url).json()
        except Exception as e:
            json_response = ''
            logging.error(e)
        return json_response

    def get_item(self, cve):
        found = False
        expired = False
        result = ""
        if cve in self.df.index:
            item = self.df.loc[cve]
            found = True
            if self.has_expired(item['last_updated']):
                expired = True
            else:
                result = json.loads(item['details'])

        if not found or expired:
            result = self.get_item_from_nvd(cve)
            self.add_item(cve, json.dumps(result))
        return result

    def get_item_from_nvd(self, cve):
        json_response = self.get_updated_entry(cve)
        if type(json_response) is str:
            return json.loads(json_response)
        else:
            return json_response

    def add_item(self, cve, details):
        cursor = self.sqlite_connection.cursor()
        last_updated = datetime.now()
        cursor.execute('''INSERT INTO {} (cve, details, last_updated)
                  VALUES(?,?,?)'''.format(self.sqlite_table), (cve, details, last_updated))
        self.sqlite_connection.commit()
        self.df.loc[cve] = {'details': details, 'last_updated': last_updated}
        logging.info('cve {} was written to the database and added to the cache '.format(cve))

    def import_df_entry(self, item):
        if ((item['details'] == '') or self.has_expired(item['last_updated'])):
            # and (self.items_found <= self.items_found_max):
            json_response = self.get_updated_entry(item.name)
            item['details'] = json.dumps(json_response)
            item['last_updated'] = datetime.now()
            self.items_found += 1
            logging.info("{} items updated ".format(self.items_found))
        return item

    def table_exists(self, create_ifnot=False):
        cursor = self.sqlite_connection.cursor()
        cursor.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name= ?  ''',
                       [self.sqlite_table])
        # if the count is 1, then table exists
        result = cursor.fetchone()[0] == 1
        return result

    def close(self):
        self.sqlite_connection.close()


if __name__ == "__main__":
    nvd_cache = NvdCache()
    nvd_cache.create_for_cve_list('cves-list.txt')
