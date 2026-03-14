import scrapy


class CheckoutItem(scrapy.Item):
    # ---- Core ----
    start_url = scrapy.Field()
    checkout_page_url = scrapy.Field()
    error = scrapy.Field()

    # ---- 3DS Analysis ----
    negative_3ds_indicators_found = scrapy.Field()
    positive_3ds_indicators_found = scrapy.Field()      # NEW — Stage 2
    likely_skips_3ds = scrapy.Field()
    confidence = scrapy.Field()                          # NEW — HIGH/MEDIUM/LOW
    analysis_method = scrapy.Field()

    # ---- Stage 2: State Machine ----
    payment_page_reached = scrapy.Field()                # NEW
    state_log = scrapy.Field()                           # NEW — full transition trace
    screenshots = scrapy.Field()                         # NEW — {label: filepath}
    auth_wall_detected = scrapy.Field()                  # NEW — guest checkout failure
    bin_trigger_psp = scrapy.Field()                     # NEW — detected PSP name
    bin_trigger_card_prefix = scrapy.Field()             # NEW — first 6 digits used

    # ---- Playwright / Interaction ----
    interaction_steps_taken = scrapy.Field()
    detected_3ds_iframe_patterns = scrapy.Field()
    detected_3ds_redirect_url = scrapy.Field()
    network_log_summary = scrapy.Field()
    browser_context_profile = scrapy.Field()
    interaction_final_url = scrapy.Field()
    interaction_duration_s = scrapy.Field()
    detected_3ds_timing_s = scrapy.Field()
    playwright_trace_file = scrapy.Field()

    # ---- Target Info ----
    target_source = scrapy.Field()
    target_vertical = scrapy.Field()
    interaction_platform = scrapy.Field()

    # ---- Infrastructure Enrichment ----
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

    # ---- Scoring ----
    risk_score = scrapy.Field()
    risk_score_details = scrapy.Field()
    last_scanned_timestamp = scrapy.Field()
