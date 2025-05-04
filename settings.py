
import os

FEEDS = {
    'checkout_results.json': {
        'format': 'json',
        'encoding': 'utf8',
        'store_empty': False,
        'fields': [
            'start_url', 'checkout_page_url', 'likely_skips_3ds',
            'negative_3ds_indicators_found', 'analysis_method', 'error',
            'interaction_steps_taken', 'detected_3ds_iframe_patterns',
            'detected_3ds_redirect_url', 'network_log_summary',
            'shodan_ports', 'shodan_org', 'shodan_vulns',
            'asn', 'asn_org', 'asn_country', 'asn_registry',
            'risk_score', 'last_scanned_timestamp'
        ],
        'indent': 4,
    }
}

LOG_LEVEL = 'INFO'

# Playwright Integration
DOWNLOAD_HANDLERS = {
    "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
    "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
}
TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
PLAYWRIGHT_BROWSER_TYPE = 'chromium'

# API Keys (Environment Variables)
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', None)
SECURITYTRAILS_API_KEY = os.environ.get('SECURITYTRAILS_API_KEY', None)

# Browser Profiles (Example)
BROWSER_PROFILES = {
    'default': {
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0 Safari/537.36',
        'locale': 'en-GB',
    },
    'us_mobile': {
        'user_agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X)...',
        'locale': 'en-US',
        'viewport': {'width': 390, 'height': 844},
        'is_mobile': True
    }
}

# Pipeline Setup
ITEM_PIPELINES = {
    'twofa_crawler.pipelines.DomainIpPipeline': 100,
    'twofa_crawler.pipelines.ShodanEnrichmentPipeline': 200,
    'twofa_crawler.pipelines.ASNEnrichmentPipeline': 300,
    'twofa_crawler.pipelines.InfrastructureEnrichmentPipeline': 400,
    'twofa_crawler.pipelines.RiskScoringPipeline': 850,
}

ROBOTSTXT_OBEY = False


# Playwright Integration
DOWNLOAD_HANDLERS = {
    "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
    "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
}
TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
PLAYWRIGHT_BROWSER_TYPE = 'chromium'

# API Keys and Config
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
ASN_API_URL = os.getenv("ASN_API_URL", "")

# Pipelines
ITEM_PIPELINES = {
    'twofa_crawler.pipelines.DomainIpPipeline': 100,
    'twofa_crawler.pipelines.ShodanEnrichmentPipeline': 200,
    'twofa_crawler.pipelines.ASNEnrichmentPipeline': 300,
}

ROBOTSTXT_OBEY = False
