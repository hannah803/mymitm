from scrapy import Spider, Selector
from myscraper.items import MyscraperItem
from myscraper.pipelines import MyscraperPipeline

class top100(Spider):
	name, start_urls = 'top100', ['http://www.chinarank.org.cn/top100/Rank.do?page=1', 'http://www.chinarank.org.cn/top100/Rank.do?page=2', 'http://www.chinarank.org.cn/top100/Rank.do?page=3','http://www.chinarank.org.cn/top100/Rank.do?page=4', 'http://www.chinarank.org.cn/top100/Rank.do?page=5']

	def parse(self, response):
		sel = Selector(response)
		item = MyscraperItem()
		item['link'] = sel.xpath('*//a/@href').re("\.\./overview/Info\.do\?url=.*")
		#item['link'] = sel.xpath('*//a/@href').extract()
		#item['link'] = sel.xpath('*//a/@href')
		print item['link']
		p = MyscraperPipeline()
		p.process_item(item)
