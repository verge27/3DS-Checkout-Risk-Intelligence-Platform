# middlewares.py — Red Team Stealth Middleware (Merged)
# Combines full fingerprint spoofing suite with robust Scrapy-Playwright integration.
# Only applies stealth once per page context to avoid race conditions on sub-resource requests.

import random
import asyncio
from playwright_stealth import stealth_async


class RedTeamStealthMiddleware:
    """
    Scrapy downloader middleware for advanced browser fingerprint evasion.
    
    Applies stealth patches, randomised fingerprints, and exposes a
    HumanInteractionHandler via request.meta['interaction'] for use in spiders.
    
    Only triggers on requests with playwright=True in meta.
    Stealth is applied once per page context (guarded by 'stealth_applied' flag).
    """

    def __init__(self, settings):
        self.settings = settings

    @classmethod
    def from_crawler(cls, crawler):
        return cls(crawler.settings)

    async def process_request(self, request, spider):
        # Gate: only act on Playwright-driven requests
        if not request.meta.get("playwright"):
            return None

        page = request.meta.get("playwright_page")
        if not page:
            return None

        # Single-apply guard — prevents re-injection on sub-resource requests
        if not request.meta.get("stealth_applied"):
            # Core stealth patches (navigator, permissions, webdriver flag, etc.)
            await stealth_async(page, chrome_stealth=True, init_scripts_only=False)

            # Randomised fingerprint overlay
            profile = self._generate_fingerprint_profile()
            await self._apply_fingerprint(page, profile)

            # Expose interaction handler for spider-level use
            request.meta["interaction"] = HumanInteractionHandler(page)
            request.meta["stealth_applied"] = True

        return None

    # -------------------------------------------------------------------------
    # Fingerprint generation
    # -------------------------------------------------------------------------

    def _generate_fingerprint_profile(self):
        """Build a randomised browser fingerprint profile."""
        return {
            "viewport": {
                "width": random.randint(1280, 1920),
                "height": random.randint(720, 1080),
                "device_scale": random.choice([1, 1.25, 1.5]),
            },
            "webgl": {
                "vendor": random.choice(
                    ["Intel Inc.", "NVIDIA Corporation", "AMD"]
                ),
                "renderer": f"Intel Iris OpenGL Engine ({random.randint(5000, 6000)})",
            },
            "audio": {
                "context_hash": hex(random.getrandbits(128))[2:],
            },
            "timezone": random.choice(
                ["Europe/London", "America/New_York", "Asia/Tokyo"]
            ),
            "languages": random.choice(
                [["en-GB", "en"], ["en-US", "en"], ["fr-FR", "fr"], ["de-DE", "de"]]
            ),
        }

    # -------------------------------------------------------------------------
    # Fingerprint application
    # -------------------------------------------------------------------------

    async def _apply_fingerprint(self, page, profile):
        """Inject fingerprint overrides into the browser context."""

        # Viewport
        await page.set_viewport_size({
            "width": profile["viewport"]["width"],
            "height": profile["viewport"]["height"],
        })

        # Navigator languages + timezone spoofing
        await page.add_init_script(f"""
            Object.defineProperty(navigator, 'languages', {{
                value: {profile['languages']},
                configurable: false
            }});
            Object.defineProperty(Intl, 'DateTimeFormat', {{
                value: class extends Intl.DateTimeFormat {{
                    constructor() {{
                        super(...arguments);
                        this.resolvedOptions = () => ({{
                            ...super.resolvedOptions(),
                            timeZone: '{profile['timezone']}'
                        }});
                    }}
                }},
                configurable: true
            }});
        """)

        # WebGL vendor/renderer spoofing
        await page.add_init_script(f"""
            const _getParam = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(param) {{
                if (param === 37445) return '{profile['webgl']['vendor']}';
                if (param === 37446) return '{profile['webgl']['renderer']}';
                return _getParam.call(this, param);
            }};
        """)

        # AudioContext fingerprint perturbation
        await page.add_init_script("""
            const _createOsc = AudioContext.prototype.createOscillator;
            AudioContext.prototype.createOscillator = function() {
                const osc = _createOsc.call(this);
                osc.type = 'sine';
                return osc;
            };
        """)


class HumanInteractionHandler:
    """
    Human-like browser interaction primitives.
    
    Accessed in spiders via: request.meta['interaction']
    
    Usage:
        interaction = response.meta['interaction']
        await interaction.human_click('#checkout-btn')
        await interaction.human_type('#card-number', '4111111111111111')
    """

    def __init__(self, page):
        self.page = page

    async def human_click(self, selector, **kwargs):
        """Click with randomised cursor path and timing jitter."""
        element = await self.page.wait_for_selector(selector)
        box = await element.bounding_box()

        # Offset within element bounds — avoids centre-point detection signature
        target_x = box["x"] + box["width"] * random.uniform(0.2, 0.8)
        target_y = box["y"] + box["height"] * random.uniform(0.2, 0.8)

        # Approach with slight overshoot then correct
        await self.page.mouse.move(
            target_x * random.uniform(0.95, 1.05),
            target_y * random.uniform(0.95, 1.05),
            steps=random.randint(5, 10),
        )
        await asyncio.sleep(random.uniform(0.05, 0.3))

        # Final click at precise target
        await self.page.mouse.click(
            target_x, target_y, delay=random.randint(50, 150)
        )
        await asyncio.sleep(random.uniform(0.15, 0.8))

    async def human_type(self, selector, text, **kwargs):
        """Type with per-character delay variance and natural word-boundary pauses."""
        await self.human_click(selector)

        for char in text:
            await self.page.keyboard.type(char, delay=random.randint(30, 140))

            # Occasional pause at word boundaries
            if char == " " and random.random() > 0.7:
                await asyncio.sleep(random.uniform(0.2, 1.2))

        # Post-input dwell
        await asyncio.sleep(random.uniform(0.1, 0.6))

    async def human_scroll(self, direction="down", distance=None):
        """Scroll with variable speed — useful for lazy-loaded content."""
        delta = distance or random.randint(200, 600)
        if direction == "up":
            delta = -delta

        steps = random.randint(3, 7)
        step_size = delta / steps

        for _ in range(steps):
            await self.page.mouse.wheel(0, step_size)
            await asyncio.sleep(random.uniform(0.05, 0.2))

        await asyncio.sleep(random.uniform(0.3, 1.0))
