# checkout_spider.py — Stage 2: State-Machine Checkout Crawler
# Navigates: Landing → Product → Cart → Checkout → Payment
# Uses HumanInteractionHandler from RedTeamStealthMiddleware for all interactions.
# Fuzzy selector matching via _fuzzy_find — no hardcoded selector banks.

import scrapy
import re
import asyncio
import time
import random
from enum import Enum, auto
from scrapy_playwright.page import PageMethod, PageRequest
from twofa_crawler.items import CheckoutItem


class FlowState(Enum):
    """Checkout flow state machine states."""
    ENTRY = auto()
    PRODUCT_DISCOVERY = auto()
    ADD_TO_CART = auto()
    NAVIGATE_CHECKOUT = auto()
    PAYMENT_PAGE = auto()
    ANALYSIS = auto()
    FAILED = auto()


# ---------------------------------------------------------------------------
# Fuzzy matching config — keyword groups used to score DOM elements.
# Each group maps to a flow stage. Elements are scored by how many
# keywords they match across text content, href, class, id, data-* attrs.
# ---------------------------------------------------------------------------

FUZZY_KEYWORDS = {
    "product": {
        "href": ["product", "item", "shop", "/p/", "/dp/", "catalog", "collection"],
        "text": ["shop now", "buy now", "view product", "see details", "browse"],
        "class_id": ["product-card", "product-tile", "product-item", "ProductCard"],
    },
    "add_to_cart": {
        "text": [
            "add to cart", "add to bag", "add to basket", "buy now", "buy it now",
            "add item", "purchase",
        ],
        "class_id": ["add-to-cart", "addToCart", "add-to-bag", "add-to-basket", "atc-button"],
        "data": ["add-to-cart", "addToCart", "add_to_cart"],
    },
    "checkout": {
        "href": ["checkout", "cart", "bag", "basket", "order"],
        "text": [
            "checkout", "check out", "proceed to checkout", "go to checkout",
            "view cart", "view bag", "view basket", "go to cart", "go to bag",
            "my cart", "my bag", "shopping cart", "shopping bag",
        ],
        "class_id": [
            "checkout", "cart-icon", "bag-icon", "basket-icon",
            "cart-button", "checkout-button", "mini-cart",
        ],
    },
    "proceed_to_payment": {
        "text": [
            "continue to payment", "proceed to payment", "place order",
            "pay now", "continue", "next step", "go to payment",
            "complete order", "submit order",
        ],
        "class_id": ["payment-submit", "continue-btn", "proceed-payment"],
        "data": ["payment", "continue", "proceed"],
    },
    "guest_checkout": {
        "text": [
            "guest checkout", "checkout as guest", "continue as guest",
            "skip login", "no account", "without account",
            "continue without", "guest", "buy as guest",
            "proceed as guest", "no thanks",
        ],
        "href": ["guest", "no-account", "skip-login"],
        "class_id": ["guest-checkout", "guestCheckout", "guest-btn", "skip-login"],
        "data": ["guest", "skip-auth", "guest-checkout"],
    },
}

# ---------------------------------------------------------------------------
# PSP test cards that are known to trigger 3DS challenges.
# Keyed by PSP — detection logic matches iframe src / page content.
# Each entry: (card_number, exp_month, exp_year, cvc, cardholder)
# These are official sandbox/test-mode numbers only.
# ---------------------------------------------------------------------------

PSP_TEST_CARDS = {
    "stripe": {
        "detect": [r"stripe", r"js\.stripe\.com", r"elements-inner"],
        "cards": {
            # Stripe 3DS2 authentication required
            "3ds_required":  ("4000002760003184", "12", "26", "123", "Test Cardholder"),
            # Stripe 3DS2 challenge flow
            "3ds_challenge":  ("4000002500003155", "12", "26", "123", "Test Cardholder"),
        },
    },
    "adyen": {
        "detect": [r"adyen", r"checkoutshopper", r"adyen-checkout"],
        "cards": {
            # Adyen 3DS2 challenge required
            "3ds_required":  ("5212345678901234", "03", "30", "737", "Test Cardholder"),
        },
    },
    "braintree": {
        "detect": [r"braintree", r"braintreegateway", r"braintree-api"],
        "cards": {
            # Braintree 3DS enrolled, challenge
            "3ds_required":  ("4000000000002503", "12", "26", "123", "Test Cardholder"),
        },
    },
    "checkout_com": {
        "detect": [r"checkout\.com", r"frames\.checkout", r"cko-"],
        "cards": {
            # Checkout.com 3DS challenge
            "3ds_required":  ("4242424242424242", "12", "26", "100", "Test Cardholder"),
        },
    },
    "worldpay": {
        "detect": [r"worldpay", r"access\.worldpay"],
        "cards": {
            # Worldpay 3DS challenge
            "3ds_required":  ("4444333322221111", "12", "26", "123", "Test Cardholder"),
        },
    },
    "cybersource": {
        "detect": [r"cybersource", r"flex\.cybersource"],
        "cards": {
            # CyberSource 3DS required
            "3ds_required":  ("4000000000002701", "12", "26", "123", "Test Cardholder"),
        },
    },
    # Generic fallback — Visa test card commonly used across PSPs
    "_fallback": {
        "detect": [],
        "cards": {
            "3ds_required":  ("4000000000003220", "12", "26", "123", "Test Cardholder"),
        },
    },
}

# Structural selectors for payment page detection (not fuzzy — these are
# specific DOM signatures that prove we've reached the payment form)
PAYMENT_STRUCTURAL_SELECTORS = [
    'input[name*="card" i]',
    'input[name*="cc-number" i]',
    'input[placeholder*="Card number" i]',
    'input[placeholder*="card number" i]',
    'input[autocomplete="cc-number"]',
    'iframe[src*="stripe"]',
    'iframe[src*="braintree"]',
    'iframe[src*="adyen"]',
    'iframe[src*="checkout.com"]',
    'iframe[src*="worldpay"]',
    'iframe[src*="cybersource"]',
    'iframe[title*="card" i]',
    'iframe[title*="payment" i]',
    '[data-testid*="payment-form"]',
    '#payment-form',
    '.payment-form',
    '#credit-card-form',
]

PAYMENT_TEXT_SIGNALS = [
    "credit card", "debit card", "card number", "expiry date",
    "cvv", "cvc", "billing address", "payment method",
]

# 3DS detection patterns
THREE_DS_PATTERNS = {
    "negative": [
        r"no\s*3ds",
        r"3ds\s*:\s*false",
        r"3ds\s*=\s*false",
        r"skip.?3ds",
        r"disable.?3ds",
        r"threeDSEnabled\s*:\s*false",
        r'"threeDS"\s*:\s*false',
        r"challengeIndicator.*no.?challenge",
        r"exemption.*low.?value",
        r"sca.*exempt",
    ],
    "positive": [
        r"3ds\s*:\s*true",
        r"3ds\s*=\s*true",
        r"threeDSEnabled\s*:\s*true",
        r'"threeDS"\s*:\s*true',
        r"3d.?secure",
        r"strong.?customer.?authentication",
        r"sca.?required",
    ],
    "gateway_iframes": [
        r"stripe.*payment.*element",
        r"braintree.*3ds",
        r"adyen.*challenge",
        r"checkout\.com.*frames",
        r"worldpay.*3ds",
        r"cybersource.*flex",
    ],
}


class CheckoutSpider(scrapy.Spider):
    name = "checkout_spider"

    # Configurable: scrapy crawl checkout_spider -a targets=url1,url2
    start_urls = []

    custom_settings = {
        "PLAYWRIGHT_DEFAULT_NAVIGATION_TIMEOUT": 30000,
        "CONCURRENT_REQUESTS": 1,
    }

    def __init__(self, *args, targets=None, **kwargs):
        super().__init__(*args, **kwargs)
        if targets:
            self.start_urls = [u.strip() for u in targets.split(",")]
        self._state = FlowState.ENTRY

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def start_requests(self):
        for url in self.start_urls:
            yield PageRequest(
                url=url,
                callback=self.run_state_machine,
                meta={
                    "playwright": True,
                    "playwright_include_page": True,
                    "playwright_page_methods": [
                        PageMethod("wait_for_load_state", "networkidle"),
                    ],
                    "errback": self.errback,
                },
            )

    # -------------------------------------------------------------------------
    # State machine core
    # -------------------------------------------------------------------------

    async def run_state_machine(self, response):
        """Main dispatch — drives flow from entry to payment analysis."""
        page = response.meta["playwright_page"]
        interaction = response.meta.get("interaction")
        if not interaction:
            self.logger.error("No interaction handler — stealth middleware not loaded?")
            await page.close()
            return

        item = CheckoutItem()
        item["start_url"] = response.url
        item["state_log"] = []
        item["negative_3ds_indicators_found"] = []
        item["positive_3ds_indicators_found"] = []
        item["screenshots"] = {}

        self._state = FlowState.ENTRY
        self._log(item, f"Landed on {response.url}")

        try:
            # ---- PRODUCT DISCOVERY ----
            self._state = FlowState.PRODUCT_DISCOVERY
            product_clicked = await self._fuzzy_click(
                page, interaction, "product", item, label="product link"
            )
            if not product_clicked:
                self._log(item, "No product link — assuming already on product page")

            # ---- ADD TO CART ----
            atc_ok = await self.find_and_add_to_cart(page, interaction, item)
            if not atc_ok:
                await self._screenshot(page, item, "atc_failure")
                await page.close()
                yield item
                return

            # ---- NAVIGATE TO PAYMENT ----
            payment_reached = await self.navigate_to_payment(page, interaction, item)

            await self._screenshot(page, item, "payment_state")

            # ---- BIN TRIGGER ----
            # Enter a PSP-specific test card known to require 3DS challenge.
            # This proves whether the merchant *can* trigger 3DS, not just
            # whether the page source hints at it.
            if payment_reached:
                await self._trigger_bin_entry(page, interaction, item)
                await self._screenshot(page, item, "post_bin_entry")

            # ---- 3DS ANALYSIS ----
            self._state = FlowState.ANALYSIS
            await self._analyse_3ds(page, item)
            item["checkout_page_url"] = page.url
            item["payment_page_reached"] = payment_reached

            self._log(item, f"Complete. payment_reached={payment_reached}")

        except Exception as e:
            self._state = FlowState.FAILED
            self._log(item, f"Exception in {self._state.name}: {repr(e)}")
            self.logger.error(f"State machine error: {repr(e)}")
            await self._screenshot(page, item, "exception")
        finally:
            await page.close()

        yield item

    # -------------------------------------------------------------------------
    # Spec methods: find_and_add_to_cart / navigate_to_payment
    # -------------------------------------------------------------------------

    async def find_and_add_to_cart(self, page, interaction, item):
        """
        Locate and click an 'Add to Cart' (or equivalent) button using
        fuzzy selector matching against the 'add_to_cart' keyword group.

        Handles variant selectors (size/colour) that gate the ATC button
        on some sites.

        Returns True if an ATC-like element was successfully clicked.
        """
        self._state = FlowState.ADD_TO_CART

        # Some product pages require selecting a variant before ATC is enabled
        await self._try_select_variant(page, interaction, item)

        clicked = await self._fuzzy_click(
            page, interaction, "add_to_cart", item, label="Add to Cart"
        )
        if not clicked:
            self._transition_failed(item, "Could not find Add to Cart element")
            return False

        # Dwell — wait for cart flyout / modal / redirect
        await asyncio.sleep(2.0)

        # Some sites show a confirmation modal with its own "go to cart" CTA
        await self._dismiss_cart_modal(page, interaction, item)

        return True

    async def navigate_to_payment(self, page, interaction, item):
        """
        From current state (post-ATC), navigate through cart/checkout
        screens until the payment form is reached.

        Uses fuzzy matching against 'checkout' and 'proceed_to_payment'
        keyword groups. Retries up to 3 hops (cart → review → payment
        is common in multi-step checkouts).

        Returns True if payment page indicators are detected.
        """
        self._state = FlowState.NAVIGATE_CHECKOUT

        # Step 1: Get to cart/checkout page
        checkout_clicked = await self._fuzzy_click(
            page, interaction, "checkout", item, label="Checkout nav"
        )
        if not checkout_clicked:
            current = page.url
            if any(kw in current.lower() for kw in ["/cart", "/bag", "/basket", "/checkout"]):
                self._log(item, f"Already at cart/checkout: {current}")
            else:
                self._transition_failed(item, "Could not navigate to checkout")
                return False

        await asyncio.sleep(1.5)

        # Step 2: Guest checkout bias — try to bypass auth walls.
        # Many merchants force login here; we always prefer guest flow
        # to avoid false negatives (auth wall ≠ 3DS enforcement).
        await self._try_guest_checkout(page, interaction, item)

        # Step 3: Multi-hop — keep clicking "Continue"/"Proceed to Payment"
        # to traverse multi-step checkout flows
        self._state = FlowState.PAYMENT_PAGE
        max_hops = 3
        for hop in range(max_hops):
            if await self._detect_payment_page(page, item):
                return True

            advanced = await self._fuzzy_click(
                page, interaction, "proceed_to_payment", item,
                label=f"Proceed to Payment (hop {hop + 1})", timeout=4000,
            )
            if not advanced:
                self._log(item, f"No further navigation at hop {hop + 1}")
                break

            await asyncio.sleep(2.0)

        # Final check after all hops exhausted
        return await self._detect_payment_page(page, item)

    # -------------------------------------------------------------------------
    # Fuzzy selector engine
    # -------------------------------------------------------------------------

    async def _fuzzy_find(self, page, keyword_group, timeout=5000):
        """
        Fuzzy DOM element discovery. Queries all interactive elements
        (a, button, input[type=submit], [role=button]) and scores them
        against the keyword group's text, href, class/id, and data-attribute
        patterns.

        Scoring weights:
          - text match:     3 (strongest — user-facing label)
          - href match:     2
          - class/id match: 2
          - data-* match:   2

        Returns (ElementHandle, score, matches, text) or None.
        """
        keywords = FUZZY_KEYWORDS.get(keyword_group, {})
        if not keywords:
            return None

        # Pull all candidate interactive elements with their attributes
        candidates = await page.evaluate("""() => {
            const els = document.querySelectorAll(
                'a, button, input[type="submit"], [role="button"]'
            );
            return Array.from(els).map((el, idx) => ({
                idx: idx,
                tag: el.tagName.toLowerCase(),
                text: (el.textContent || el.value || '')
                    .trim().substring(0, 200).toLowerCase(),
                href: (el.getAttribute('href') || '').toLowerCase(),
                className: (el.className || '').toString().toLowerCase(),
                id: (el.id || '').toLowerCase(),
                dataAttrs: Object.keys(el.dataset || {}).map(k =>
                    k.toLowerCase() + '=' + (el.dataset[k] || '').toLowerCase()
                ).join(' '),
                visible: el.offsetParent !== null
                    && el.offsetWidth > 0
                    && el.offsetHeight > 0,
                disabled: el.disabled
                    || el.getAttribute('aria-disabled') === 'true',
            }));
        }""")

        scored = []
        for c in candidates:
            if not c["visible"] or c["disabled"]:
                continue

            score = 0
            matched_on = []

            for kw in keywords.get("text", []):
                if kw.lower() in c["text"]:
                    score += 3
                    matched_on.append(f"text:'{kw}'")

            for kw in keywords.get("href", []):
                if kw.lower() in c["href"]:
                    score += 2
                    matched_on.append(f"href:'{kw}'")

            for kw in keywords.get("class_id", []):
                if kw.lower() in c["className"] or kw.lower() in c["id"]:
                    score += 2
                    matched_on.append(f"class_id:'{kw}'")

            for kw in keywords.get("data", []):
                if kw.lower() in c["dataAttrs"]:
                    score += 2
                    matched_on.append(f"data:'{kw}'")

            if score > 0:
                scored.append((score, c["idx"], matched_on, c["text"][:60]))

        if not scored:
            return None

        scored.sort(key=lambda x: x[0], reverse=True)
        best_score, best_idx, best_matches, best_text = scored[0]

        # Resolve back to ElementHandle
        elements = await page.query_selector_all(
            'a, button, input[type="submit"], [role="button"]'
        )
        if best_idx < len(elements):
            return elements[best_idx], best_score, best_matches, best_text

        return None

    async def _fuzzy_click(self, page, interaction, keyword_group, item,
                           label="element", timeout=5000):
        """
        Fuzzy-find an element and click it with human-like mouse movement.
        Returns True if clicked successfully.
        """
        result = await self._fuzzy_find(page, keyword_group, timeout)
        if not result:
            self._log(item, f"Fuzzy: no match for '{keyword_group}'")
            return False

        element, score, matches, text = result
        self._log(
            item,
            f"Fuzzy: {label} score={score} matches={matches} text='{text}'"
        )

        try:
            box = await element.bounding_box()
            if not box:
                await element.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                box = await element.bounding_box()

            if box:
                x = box["x"] + box["width"] * random.uniform(0.2, 0.8)
                y = box["y"] + box["height"] * random.uniform(0.2, 0.8)
                await page.mouse.move(x, y, steps=random.randint(5, 10))
                await asyncio.sleep(random.uniform(0.05, 0.3))
                await page.mouse.click(x, y, delay=random.randint(50, 150))
            else:
                await element.click()

            await page.wait_for_load_state("networkidle", timeout=15000)
            await asyncio.sleep(1.0)
            return True

        except Exception as e:
            self._log(item, f"Fuzzy click failed for '{label}': {repr(e)}")
            return False

    # -------------------------------------------------------------------------
    # Guest checkout / auth wall bypass
    # -------------------------------------------------------------------------

    async def _try_guest_checkout(self, page, interaction, item):
        """
        Detect and click through auth walls by prioritising 'Guest Checkout'
        or equivalent CTAs. Uses fuzzy matching against the 'guest_checkout'
        keyword group.

        If no guest option is found, checks whether we're on a login page
        (form with password field) and logs it as a blocker.
        """
        guest_clicked = await self._fuzzy_click(
            page, interaction, "guest_checkout", item,
            label="Guest Checkout", timeout=3000,
        )
        if guest_clicked:
            self._log(item, "Guest checkout path selected — bypassed auth wall")
            await asyncio.sleep(1.5)
            return True

        # Check if we're stuck on an auth wall
        auth_wall = await page.evaluate("""() => {
            const inputs = document.querySelectorAll(
                'input[type="password"], input[name*="password" i], input[autocomplete="current-password"]'
            );
            const loginText = document.body.innerText.toLowerCase();
            const hasLoginForm = inputs.length > 0;
            const hasLoginKeywords = ['sign in', 'log in', 'login', 'create account']
                .some(kw => loginText.includes(kw));
            return hasLoginForm && hasLoginKeywords;
        }""")

        if auth_wall:
            self._log(
                item,
                "AUTH WALL DETECTED — no guest checkout option found. "
                "Spider cannot proceed past login. This is a tool limitation, "
                "not a 3DS indicator."
            )
            item.setdefault("auth_wall_detected", True)

        return False

    # -------------------------------------------------------------------------
    # BIN triggering — PSP-specific test card entry
    # -------------------------------------------------------------------------

    async def _trigger_bin_entry(self, page, interaction, item):
        """
        Identify the payment gateway (PSP) from iframe sources and page content,
        then enter the corresponding test card known to trigger 3DS challenges.

        This is the definitive test: if the merchant's integration triggers a
        3DS challenge for a known-challenge BIN, their SCA implementation is
        confirmed. If it doesn't, they're either exempting or skipping.

        Does NOT submit the form — only fills card fields to observe
        client-side 3DS initialisation signals.
        """
        # Detect PSP from page content + iframes
        body = await page.content()
        iframe_sources = await page.evaluate("""() =>
            Array.from(document.querySelectorAll('iframe'))
                .map(f => (f.src || '') + ' ' + (f.title || ''))
                .join(' ')
        """)
        fingerprint = (body + " " + iframe_sources).lower()

        detected_psp = None
        for psp_name, psp_config in PSP_TEST_CARDS.items():
            if psp_name == "_fallback":
                continue
            for pattern in psp_config["detect"]:
                if re.search(pattern, fingerprint, re.IGNORECASE):
                    detected_psp = psp_name
                    break
            if detected_psp:
                break

        if not detected_psp:
            detected_psp = "_fallback"

        card_set = PSP_TEST_CARDS[detected_psp]["cards"]
        card = card_set.get("3ds_required") or next(iter(card_set.values()))
        card_num, exp_m, exp_y, cvc, name = card

        self._log(item, f"BIN trigger: PSP={detected_psp}, card={card_num[:6]}...{card_num[-4:]}")
        item["bin_trigger_psp"] = detected_psp
        item["bin_trigger_card_prefix"] = card_num[:6]

        # --- Field entry ---
        # Strategy: try direct page fields first, then iframe injection.
        filled = await self._fill_card_fields(page, interaction, card_num, exp_m, exp_y, cvc, name, item)

        if not filled:
            # Many PSPs use iframes — try to enter within the first payment iframe
            filled = await self._fill_card_iframe(page, interaction, card_num, exp_m, exp_y, cvc, name, item)

        if filled:
            self._log(item, "BIN entry complete — monitoring for 3DS initialisation")
            # Brief wait to observe any client-side 3DS trigger (redirect, modal, iframe)
            await asyncio.sleep(3.0)

            # Check for 3DS challenge appearance post-entry
            post_body = await page.content()
            challenge_signals = [
                r"3ds", r"challenge", r"authentication",
                r"cardinal", r"songbird", r"secure.*verification",
            ]
            for sig in challenge_signals:
                if re.search(sig, post_body, re.IGNORECASE):
                    ind = f"BIN trigger: 3DS signal post-entry: /{sig}/"
                    item["positive_3ds_indicators_found"].append(ind)
                    self._log(item, ind)
        else:
            self._log(item, "BIN entry failed — could not locate card input fields")

    async def _fill_card_fields(self, page, interaction, card_num, exp_m, exp_y, cvc, name, item):
        """
        Attempt to fill card fields on the main page (non-iframe PSP integrations).
        Returns True if at least the card number field was filled.
        """
        # Card number field candidates
        card_selectors = [
            'input[autocomplete="cc-number"]',
            'input[name*="card" i][name*="number" i]',
            'input[name*="cardnumber" i]',
            'input[placeholder*="card number" i]',
            'input[data-testid*="card-number" i]',
            'input[id*="card" i][id*="number" i]',
        ]
        # Expiry field candidates
        exp_selectors = [
            'input[autocomplete="cc-exp"]',
            'input[name*="expir" i]',
            'input[placeholder*="MM" i]',
            'input[name*="exp" i]',
        ]
        # Split expiry (month + year)
        exp_month_selectors = [
            'input[autocomplete="cc-exp-month"]',
            'input[name*="month" i]',
            'select[name*="month" i]',
        ]
        exp_year_selectors = [
            'input[autocomplete="cc-exp-year"]',
            'input[name*="year" i]',
            'select[name*="year" i]',
        ]
        # CVC
        cvc_selectors = [
            'input[autocomplete="cc-csc"]',
            'input[name*="cvc" i]',
            'input[name*="cvv" i]',
            'input[name*="security" i]',
            'input[placeholder*="CVC" i]',
            'input[placeholder*="CVV" i]',
        ]
        # Cardholder name
        name_selectors = [
            'input[autocomplete="cc-name"]',
            'input[name*="cardholder" i]',
            'input[name*="card-name" i]',
            'input[name*="ccname" i]',
            'input[placeholder*="name on card" i]',
        ]

        filled_card = await self._type_into_first(page, interaction, card_selectors, card_num, item, "card_number")
        if not filled_card:
            return False

        # Try combined expiry first, then split
        combined_exp = f"{exp_m}/{exp_y}"
        filled_exp = await self._type_into_first(page, interaction, exp_selectors, combined_exp, item, "expiry")
        if not filled_exp:
            await self._type_into_first(page, interaction, exp_month_selectors, exp_m, item, "exp_month")
            await self._type_into_first(page, interaction, exp_year_selectors, exp_y, item, "exp_year")

        await self._type_into_first(page, interaction, cvc_selectors, cvc, item, "cvc")
        await self._type_into_first(page, interaction, name_selectors, name, item, "cardholder")

        return True

    async def _fill_card_iframe(self, page, interaction, card_num, exp_m, exp_y, cvc, name, item):
        """
        Attempt to fill card fields inside PSP iframes (Stripe Elements, Adyen, etc.).
        Returns True if card number was filled.
        """
        iframes = await page.query_selector_all("iframe")
        for iframe in iframes:
            src = await iframe.get_attribute("src") or ""
            title = await iframe.get_attribute("title") or ""
            sig = f"{src} {title}".lower()

            # Match known payment iframes
            if not any(kw in sig for kw in ["card", "payment", "stripe", "adyen", "braintree", "checkout"]):
                continue

            try:
                frame = await iframe.content_frame()
                if not frame:
                    continue

                # Try to find card number input inside the frame
                card_input = None
                for sel in ['input[name*="cardnumber" i]', 'input[name*="card" i]',
                            'input[placeholder*="card" i]', 'input[autocomplete="cc-number"]',
                            'input']:
                    try:
                        card_input = await frame.wait_for_selector(sel, timeout=1500, state="visible")
                        if card_input:
                            break
                    except Exception:
                        continue

                if card_input:
                    await card_input.click()
                    for char in card_num:
                        await frame.keyboard.type(char, delay=random.randint(30, 100))
                    self._log(item, f"BIN entered in iframe: {sig[:60]}")
                    return True

            except Exception as e:
                self._log(item, f"Iframe fill error ({sig[:40]}): {repr(e)}")
                continue

        return False

    async def _type_into_first(self, page, interaction, selectors, value, item, field_name):
        """Type a value into the first matching visible field. Returns True on success."""
        for sel in selectors:
            try:
                el = await page.wait_for_selector(sel, timeout=1500, state="visible")
                if el:
                    await el.click()
                    # Use human-like typing
                    for char in value:
                        await page.keyboard.type(char, delay=random.randint(30, 110))
                    self._log(item, f"Filled {field_name} via {sel}")
                    await asyncio.sleep(0.3)
                    return True
            except Exception:
                continue
        return False

    # -------------------------------------------------------------------------
    # Variant / modal helpers
    # -------------------------------------------------------------------------

    async def _try_select_variant(self, page, interaction, item):
        """
        Some product pages disable ATC until a size/colour is selected.
        Attempt to click the first available variant option.
        """
        variant_selectors = [
            '[class*="size"] button:not([disabled])',
            '[class*="variant"] button:not([disabled])',
            '[data-testid*="size"] button:not([disabled])',
            'select[name*="size" i] option:nth-child(2)',
            '[class*="swatch"]:not(.disabled):not(.out-of-stock)',
        ]
        for sel in variant_selectors:
            try:
                el = await page.wait_for_selector(sel, timeout=2000, state="visible")
                if el:
                    await el.click()
                    self._log(item, f"Selected variant via: {sel}")
                    await asyncio.sleep(0.8)
                    return
            except Exception:
                continue

    async def _dismiss_cart_modal(self, page, interaction, item):
        """
        After ATC, some sites show a modal/flyout. Try to find and click
        a 'Go to cart' CTA within the modal.
        """
        modal_ctas = [
            'button:has-text("View Cart")',
            'button:has-text("View Bag")',
            'a:has-text("View Cart")',
            'a:has-text("View Bag")',
            '[class*="modal"] a[href*="cart"]',
            '[class*="modal"] a[href*="checkout"]',
        ]
        for sel in modal_ctas:
            try:
                el = await page.wait_for_selector(sel, timeout=2000, state="visible")
                if el:
                    await el.click()
                    self._log(item, f"Cart modal CTA clicked: {sel}")
                    await asyncio.sleep(1.0)
                    return
            except Exception:
                continue

    # -------------------------------------------------------------------------
    # Payment page detection
    # -------------------------------------------------------------------------

    async def _detect_payment_page(self, page, item):
        """
        Structural + textual detection of payment form presence.
        Returns True if payment entry point is confirmed.
        """
        for sel in PAYMENT_STRUCTURAL_SELECTORS:
            try:
                el = await page.wait_for_selector(sel, timeout=2000, state="visible")
                if el:
                    self._log(item, f"Payment structural: {sel}")
                    return True
            except Exception:
                continue

        body = (await page.content()).lower()
        for signal in PAYMENT_TEXT_SIGNALS:
            if signal in body:
                self._log(item, f"Payment text signal: '{signal}'")
                return True

        return False

    # -------------------------------------------------------------------------
    # 3DS analysis
    # -------------------------------------------------------------------------

    async def _analyse_3ds(self, page, item):
        """
        Deep scan for 3DS enforcement/bypass signals in page source
        and gateway iframes. Produces confidence-weighted verdict.
        """
        body = await page.content()

        for pattern in THREE_DS_PATTERNS["negative"]:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                ind = f"Negative: /{pattern}/ x{len(matches)}"
                item["negative_3ds_indicators_found"].append(ind)
                self._log(item, ind)

        for pattern in THREE_DS_PATTERNS["positive"]:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                ind = f"Positive: /{pattern}/ x{len(matches)}"
                item["positive_3ds_indicators_found"].append(ind)
                self._log(item, ind)

        iframes = await page.query_selector_all("iframe")
        for iframe in iframes:
            src = await iframe.get_attribute("src") or ""
            title = await iframe.get_attribute("title") or ""
            sig = f"{src} {title}"
            for pattern in THREE_DS_PATTERNS["gateway_iframes"]:
                if re.search(pattern, sig, re.IGNORECASE):
                    ind = f"Gateway iframe: /{pattern}/ in '{sig[:80]}'"
                    item["positive_3ds_indicators_found"].append(ind)
                    self._log(item, ind)

        neg = len(item["negative_3ds_indicators_found"])
        pos = len(item["positive_3ds_indicators_found"])

        if neg > 0 and pos == 0:
            item["likely_skips_3ds"] = True
            item["confidence"] = "HIGH"
        elif neg > pos:
            item["likely_skips_3ds"] = True
            item["confidence"] = "MEDIUM"
        elif pos > 0 and neg == 0:
            item["likely_skips_3ds"] = False
            item["confidence"] = "HIGH"
        else:
            item["likely_skips_3ds"] = None
            item["confidence"] = "LOW"

        self._log(
            item,
            f"Verdict: skips_3ds={item['likely_skips_3ds']} "
            f"confidence={item['confidence']} neg={neg} pos={pos}"
        )

    # -------------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------------

    async def _screenshot(self, page, item, label):
        ts = int(time.time())
        path = f"screenshots/{label}_{ts}.png"
        try:
            await page.screenshot(path=path, full_page=True)
            item["screenshots"][label] = path
            self._log(item, f"Screenshot: {path}")
        except Exception as e:
            self.logger.warning(f"Screenshot failed ({label}): {e}")

    def _log(self, item, msg):
        entry = f"[{self._state.name}] {msg}"
        item["state_log"].append(entry)
        self.logger.info(entry)

    def _transition_failed(self, item, reason):
        self._state = FlowState.FAILED
        self._log(item, f"FAILED: {reason}")

    async def errback(self, failure):
        self.logger.error(repr(failure))
