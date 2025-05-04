import scrapy
from scrapy_playwright.page import PageMethod, PageRequest
from twofa_crawler.items import CheckoutItem
import re

class CheckoutSpider(scrapy.Spider):
    name = "checkout_spider"
    start_urls = [
        "https://example.com/checkout"  # Replace with real targets
    ]

    def start_requests(self):
        for url in self.start_urls:
            yield PageRequest(
                url=url,
                callback=self.parse_checkout,
                meta={
                    "playwright": True,
                    "playwright_include_page": True,
                    "playwright_page_methods": [
                        PageMethod("wait_for_load_state", "networkidle")
                    ],
                    "errback": self.errback
                }
            )

    async def parse_checkout(self, response):
        item = CheckoutItem()
        item["start_url"] = response.url
        item["checkout_page_url"] = response.url
        item["negative_3ds_indicators_found"] = []

        page = response.meta["playwright_page"]

        body = await page.content()
        if "no 3ds" in body.lower() or re.search(r"3ds\s*:\s*false", body):
            item["negative_3ds_indicators_found"].append("Keyword: 'no 3ds' or '3ds: false'")
            item["likely_skips_3ds"] = True
        else:
            item["likely_skips_3ds"] = False

        await page.close()
        yield item

    async def errback(self, failure):
        self.logger.error(repr(failure))
