# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html

import json
class MyscraperPipeline(object):
    def __init__(self):
        self.file = open('domain', 'a')
    def process_item(self, item):
        r = []
        #line = json.dumps(dict(item)) + "\n"
        l = {}.fromkeys(item['link']).keys()
        for i in l:
            s = i.split('_')[2]
            r.append(s[:-5])
        self.file.write('\n'.join(r))
        return item
