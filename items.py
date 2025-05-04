
import scrapy

class CheckoutItem(scrapy.Item):
    # Basic
    start_url = scrapy.Field()
    checkout_page_url = scrapy.Field()
    negative_3ds_indicators_found = scrapy.Field()
    analysis_method = scrapy.Field()
    likely_skips_3ds = scrapy.Field()
    error = scrapy.Field()

    # Playwright/Interaction
    interaction_steps_taken = scrapy.Field()
    detected_3ds_iframe_patterns = scrapy.Field()
    detected_3ds_redirect_url = scrapy.Field()
    network_log_summary = scrapy.Field()
    browser_context_profile = scrapy.Field()
    interaction_final_url = scrapy.Field()
    interaction_duration_s = scrapy.Field()
    detected_3ds_timing_s = scrapy.Field()
    playwright_trace_file = scrapy.Field()

    # Target Info
    target_source = scrapy.Field()
    target_vertical = scrapy.Field()
    interaction_platform = scrapy.Field()

    # Infrastructure Enrichment
    domain = scrapy.Field()
    ip_addresses = scrapy.Field()
    shodan_data = scrapy.Field()
    shodan_ports = scrapy.Field()
    shodan_org = scrapy.Field()
    shodan_vulns = scrapy.Field()
    asn = scrapy.Field()
    asn_org = scrapy.Field()
    asn_country = scrapy.Field()
    asn_registry = scrapy.Field()
    cdn_provider = scrapy.Field()
    tls_protocol_versions = scrapy.Field()
    tls_cipher_suite = scrapy.Field()
    tls_certificate_issuer = scrapy.Field()
    passive_dns_history = scrapy.Field()
    whois_registrar = scrapy.Field()
    whois_creation_date = scrapy.Field()
    domain_age_days = scrapy.Field()

    # Scoring
    risk_score = scrapy.Field()
    risk_score_details = scrapy.Field()
    last_scanned_timestamp = scrapy.Field()


    # Enrichment Fields
    domain = scrapy.Field()
    ip_addresses = scrapy.Field()
    shodan_data = scrapy.Field()
    shodan_ports = scrapy.Field()
    shodan_org = scrapy.Field()
    shodan_vulns = scrapy.Field()
    asn = scrapy.Field()
    asn_org = scrapy.Field()
    asn_country = scrapy.Field()
    asn_registry = scrapy.Field()

    # Infrastructure Intelligence
    cdn_provider = scrapy.Field()
    tls_protocol_versions = scrapy.Field()
    tls_certificate_issuer = scrapy.Field()
    domain_age_days = scrapy.Field()

    # Meta
    risk_score = scrapy.Field()
    last_scanned_timestamp = scrapy.Field()
