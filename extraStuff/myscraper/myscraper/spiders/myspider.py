from scrapy import Spider, Selector
from myscraper.items import MyscraperItem
from myscraper.pipelines import MyscraperPipeline

class top100(Spider):
    name, start_urls = 'top100', ['http://top.chinaz.com/list.aspx?p=1&t=256', 'http://top.chinaz.com/list.aspx?p=2&t=256', 'http://top.chinaz.com/list.aspx?p=3&t=256','http://top.chinaz.com/list.aspx?p=4&t=256', 'http://top.chinaz.com/list.aspx?p=5&t=256', 'http://top.chinaz.com/list.aspx?p=6&t=256']

    def parse(self, response):
        sel = Selector(response)
        item = MyscraperItem()
        item['link'] = sel.xpath('*//a/@href').re("/t_256/site_.*")
        #item['link'] = sel.xpath('*//a/@href').extract()
        #item['link'] = sel.xpath('*//a/@href')
        print item['link']
        p = MyscraperPipeline()
        p.process_item(item)
