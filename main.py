import asyncio
import re
import time
import logging
from urllib.parse import urljoin
from typing import List, Dict, Set
from fastapi import FastAPI, HTTPException
from pydantic import HttpUrl
from playwright.async_api import async_playwright
from seleniumwire import webdriver
from seleniumwire import webdriver
from bs4 import BeautifulSoup
import aiohttp
import tls_client

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Dictionaries (as defined above)
PAYMENT_INDICATOR_REGEX = [
    re.compile(re.escape(kw), re.IGNORECASE)
    for kw in [
        # Core purchase flow
        "cart", "checkout", "payment", "pay", "buy", "purchase", "order", "billing",
        "invoice", "transaction", "secure-checkout", "confirm-purchase", "complete-order",
        "place-order", "express-checkout", "quick-buy", "buy-now", "shop-now",

        # Subscription & upgrades
        "subscribe", "trial", "renew", "upgrade", "membership", "plans",

        # Promotions, coupons, gift cards
        "apply-coupon", "discount-code", "gift-card", "promo-code", "redeem-code",

        # Payment info/forms
        "payment-method", "payment-details", "payment-form",

        # Pricing pages
        "pricing", "plans", "pricing-plan",

        # BNPL / donate / support
        "donate", "support", "pledge", "give",
    ]
]
NON_HTML_EXTENSIONS = [
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
    ".ico", ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".mp4", ".avi", ".mov",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".wav", ".flac"
]
IGNORE_IF_URL_CONTAINS = [
    # Common asset/content folders
    "wp-content", "wp-includes", 'youtube.com', 'www.youtube.com', 'https://youtube.com', 'https://www.youtube.com', "gstatic.com/instantbuy/svg/transparent_square.svg", "skin/frontend", "/assets/", 'assets' "gstatic.com", ".svg", "transparent_square.svg", "cdn.cookielaw.org", "cookiebot.com", "clarity.ms", "sentry.io", "cdn.jsdelivr.net", "fonts.gstatic.com", "doubleclick.net", "segment.com", "matomo.org", "bam.nr-data.net", "/browser/vitals", "/themes/", "/static/", "/media/", "/images/", "/img/",

    "https://facebook.com", "youtubei/v1/log_event", "https://play.google.com", "google.com/log", "https://googlemanager.com", "consentcdn.cookiebot.com", "https://hb.imgix.net", "https://content-autofill.googleapis.com", "cookiebot.com", "https://static.klaviyo.com", "static.klaviyo.com", "https://content-autofill.googleapis.com",
    "content-autofill.googleapis.com", "https://www.google.com", "https://googleads.g.doubleclick.net", "googleads.g.doubleclick.net", "googleads.g.doubleclick.net",
    "https://www.googletagmanager.com", "googletagmanager.com", "https://www.googleadservices.com", "googleadservices.com", "https://fonts.googleapis.com",
    "fonts.googleapis.com", "http://clients2.google.com", "clients2.google.com", "https://analytics.google.com", "hanalytics.google.com",
    
    # Analytics & marketing scripts
    "googleapis", "gstatic", "googletagmanager", "google-analytics", "analytics", "doubleclick.net", 
    "facebook.net", "fbcdn", "pixel.", "tiktokcdn", "matomo", "segment.io", "clarity.ms", "mouseflow", "hotjar", 
    
    # Fonts, icons, visual only
    "fonts.", "fontawesome", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".ico", ".svg",
    
    # CDN & framework scripts
    "cdn.jsdelivr.net", "cloudflareinsights.com", "cdnjs", "bootstrapcdn", "polyfill.io", 
    "jsdelivr.net", "unpkg.com", "yastatic.net", "akamai", "fastly", 
    
    # Media, tracking images
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".svg", ".ico", 
    
    # Useless scripts/styles
    ".css", ".scss", ".less", ".map", ".js", "main.js", "bundle.js", "common.js", "theme.js", "style.css", "custom.css",

    # Other non-payment known paths
    "/favicon", "/robots.txt", "/sitemap", "/manifest", "/rss", "/feed", "/help", "/support", "/about", "/terms", "/privacy",
]

GATEWAY_KEYWORDS = {
    "stripe": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'stripe\.com', r'api\.stripe\.com/v1', r'js\.stripe\.com', r'stripe\.js', r'stripe\.min\.js',
        r'client_secret', r'payment_intent', r'data-stripe', r'stripe-payment-element',
        r'stripe-elements', r'stripe-checkout', r'hooks\.stripe\.com', r'm\.stripe\.network',
        r'stripe__input', r'stripe-card-element', r'stripe-v3ds', r'confirmCardPayment',
        r'createPaymentMethod', r'stripePublicKey', r'stripe\.handleCardAction',
        r'elements\.create', r'js\.stripe\.com/v3/hcaptcha-invisible', r'js\.stripe\.com/v3',
        r'stripe\.createToken', r'stripe-payment-request', r'stripe__frame',
        r'api\.stripe\.com/v1/payment_methods', r'js\.stripe\.com', r'api\.stripe\.com/v1/tokens',
        r'stripe\.com/docs', r'checkout\.stripe\.com', r'stripe-js', r'stripe-redirect',
        r'stripe-payment', r'stripe\.network', r'stripe-checkout\.js'
    ]],
    "paypal": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.paypal\.com', r'paypal\.com', r'paypal-sdk\.com', r'paypal\.js', r'paypalobjects\.com', r'paypal_express_checkout', r'e\.PAYPAL_EXPRESS_CHECKOUT',
        r'paypal-button', r'paypal-checkout-sdk', r'paypal-sdk\.js', r'paypal-smart-button', r'paypal_express_checkout/api',
        r'paypal-rest-sdk', r'paypal-transaction', r'itch\.io/api-transaction/paypal',
        r'PayPal\.Buttons', r'paypal\.Buttons', r'data-paypal-client-id', r'paypal\.com/sdk/js',
        r'paypal\.Order\.create', r'paypal-checkout-component', r'api-m\.paypal\.com', r'paypal-funding',
        r'paypal-hosted-fields', r'paypal-transaction-id', r'paypal\.me', r'paypal\.com/v2/checkout',
        r'paypal-checkout', r'paypal\.com/api', r'sdk\.paypal\.com', r'gotopaypalexpresscheckout'
    ]],
    "braintree": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.braintreegateway\.com/v1', r'braintreepayments\.com', r'js\.braintreegateway\.com',
        r'client_token', r'braintree\.js', r'braintree-hosted-fields', r'braintree-dropin', r'braintree-v3',
        r'braintree-client', r'braintree-data-collector', r'braintree-payment-form', r'braintree-3ds-verify',
        r'client\.create', r'braintree\.min\.js', r'assets\.braintreegateway\.com', r'braintree\.setup',
        r'data-braintree', r'braintree\.tokenize', r'braintree-dropin-ui', r'braintree\.com'
    ]],
    "adyen": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkoutshopper-live\.adyen\.com', r'adyen\.com/hpp', r'adyen\.js', r'data-adyen',
        r'adyen-checkout', r'adyen-payment', r'adyen-components', r'adyen-encrypted-data',
        r'adyen-cse', r'adyen-dropin', r'adyen-web-checkout', r'live\.adyen-services\.com',
        r'adyen\.encrypt', r'checkoutshopper-test\.adyen\.com', r'adyen-checkout__component',
        r'adyen\.com/v1', r'adyen-payment-method', r'adyen-action', r'adyen\.min\.js', r'adyen\.com'
    ]],
    "authorize.net": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'authorize\.net/gateway/transact\.dll', r'js\.authorize\.net/v1/Accept\.js', r'js\.authorize\.net',
        r'anet\.js', r'data-authorize', r'authorize-payment', r'apitest\.authorize\.net',
        r'accept\.authorize\.net', r'api\.authorize\.net', r'authorize-hosted-form',
        r'merchantAuthentication', r'data-api-login-id', r'data-client-key', r'Accept\.dispatchData',
        r'api\.authorize\.net/xml/v1', r'accept\.authorize\.net/payment', r'authorize\.net/profile'
    ]],
    "square": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'squareup\.com', r'pci-connect.squareup.com', r'js\.squarecdn\.com', r'square\.js', r'data-square', r'square-payment-form',
        r'square-checkout-sdk', r'connect\.squareup\.com', r'square\.min\.js', r'squarecdn\.com',
        r'squareupsandbox\.com', r'sandbox\.web\.squarecdn\.com', r'square-payment-flow', r'square\.card',
        r'squareup\.com/payments', r'data-square-application-id', r'square\.createPayment'
    ]],
    "klarna": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'klarna\.com', r'js\.klarna\.com', r'klarna\.js', r'data-klarna', r'klarna-checkout',
        r'klarna-onsite-messaging', r'playground\.klarna\.com', r'klarna-payments', r'klarna\.min\.js',
        r'klarna-order-id', r'klarna-checkout-container', r'klarna-load', r'api\.klarna\.com'
    ]],
    "checkout.com": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.checkout\.com', r'cko\.js', r'data-checkout', r'checkout-sdk', r'checkout-payment',
        r'js\.checkout\.com', r'secure\.checkout\.com', r'checkout\.frames\.js', r'api\.sandbox\.checkout\.com',
        r'cko-payment-token', r'checkout\.init', r'cko-hosted', r'checkout\.com/v2', r'cko-card-token'
    ]],
    "razorpay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkout\.razorpay\.com', r'razorpay\.js', r'data-razorpay', r'razorpay-checkout',
        r'razorpay-payment-api', r'razorpay-sdk', r'razorpay-payment-button', r'razorpay-order-id',
        r'api\.razorpay\.com', r'razorpay\.min\.js', r'payment_box payment_method_razorpay',
        r'razorpay', r'cdn\.razorpay\.com', r'rzp_payment_icon\.svg', r'razorpay\.checkout',
        r'data-razorpay-key', r'razorpay_payment_id', r'checkout\.razorpay\.com/v1', r'razorpay-hosted'
    ]],
    "paytm": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'securegw\.paytm\.in', r'api\.paytm\.com', r'paytm\.js', r'data-paytm', r'paytm-checkout',
        r'paytm-payment-sdk', r'paytm-wallet', r'paytm\.allinonesdk', r'securegw-stage\.paytm\.in',
        r'paytm\.min\.js', r'paytm-transaction-id', r'paytm\.invoke', r'paytm-checkout-js',
        r'data-paytm-order-id'
    ]],
    "Shopify Payments": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'pay\.shopify\.com', r'data-shopify-payments', r'shopify-checkout-sdk', r'shopify-payment-api',
        r'shopify-sdk', r'shopify-express-checkout', r'shopify_payments\.js', r'checkout\.shopify\.com',
        r'shopify-payment-token', r'shopify\.card', r'shopify-checkout-api', r'data-shopify-checkout',
        r'shopify\.com/api'
    ]],
    "worldpay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'secure\.worldpay\.com', r'worldpay\.js', r'data-worldpay', r'worldpay-checkout',
        r'worldpay-payment-sdk', r'worldpay-secure', r'secure-test\.worldpay\.com', r'worldpay\.min\.js',
        r'worldpay\.token', r'worldpay-payment-form', r'access\.worldpay\.com', r'worldpay-3ds',
        r'data-worldpay-token'
    ]],
    "2checkout": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'www\.2checkout\.com', r'2co\.js', r'data-2checkout', r'2checkout-payment', r'secure\.2co\.com',
        r'2checkout-hosted', r'api\.2checkout\.com', r'2co\.min\.js', r'2checkout\.token', r'2co-checkout',
        r'data-2co-seller-id', r'2checkout\.convertplus', r'secure\.2co\.com/v2'
    ]],
    "Amazon pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'payments\.amazon\.com', r'amazonpay\.js', r'data-amazon-pay', r'amazon-pay-button',
        r'amazon-pay-checkout-sdk', r'amazon-pay-wallet', r'amazon-checkout\.js', r'payments\.amazon\.com/v2',
        r'amazon-pay-token', r'amazon-pay-sdk', r'data-amazon-pay-merchant-id', r'amazon-pay-signin',
        r'amazon-pay-checkout-session'
    ]],
    "Apple pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'apple-pay\.js', r'generate_gpay_btn', r'google-pay/token', r'pay.google.com',  r'data-apple-pay', r'apple-pay-button', r'apple-pay-checkout-sdk',
        r'apple-pay-session', r'apple-pay-payment-request', r'ApplePaySession', r'apple-pay-merchant-id',
        r'apple-pay-payment', r'apple-pay-sdk', r'data-apple-pay-token', r'apple-pay-checkout',
        r'apple-pay-domain'
    ]],
    "Google pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'pay\.google\.com', r'googlepay\.js', r'data-google-pay', r'google-pay-button',
        r'google-pay-checkout-sdk', r'google-pay-tokenization', r'payments\.googleapis\.com',
        r'google\.payments\.api', r'google-pay-token', r'google-pay-payment-method',
        r'data-google-pay-merchant-id', r'google-pay-checkout', r'google-pay-sdk'
    ]],
    "mollie": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.mollie\.com', r'mollie\.js', r'data-mollie', r'mollie-checkout', r'mollie-payment-sdk',
        r'mollie-components', r'mollie\.min\.js', r'profile\.mollie\.com', r'mollie-payment-token',
        r'mollie-create-payment', r'data-mollie-profile-id', r'mollie-checkout-form', r'mollie-redirect'
    ]],
    "opayo": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'live\.opayo\.eu', r'opayo\.js', r'data-opayo', r'opoayo-checkout', r'opayo-payment-sdk',
        r'opayo-form', r'test\.opayo\.eu', r'opayo\.min\.js', r'opayo-payment-token', r'opayo-3ds',
        r'data-opayo-merchant-id', r'opayo-hosted', r'opayo\.api'
    ]],
    "paddle": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkout\.paddle\.com', r'paddle_button\.js', r'paddle\.js', r'data-paddle',
        r'paddle-checkout-sdk', r'paddle-product-id', r'api\.paddle\.com', r'paddle\.min\.js',
        r'paddle-checkout', r'data-paddle-vendor-id', r'paddle\.Checkout\.open', r'paddle-transaction-id',
        r'paddle-hosted'
    ]]
}



CAPTCHA_PATTERNS = {
    "reCaptcha": [
        re.compile(p, re.IGNORECASE) for p in [
            "g-recaptcha", "recaptcha/api.js", "data-sitekey", "nocaptcha",
            "recaptcha.net", "www.google.com/recaptcha", "grecaptcha.execute",
            "grecaptcha.render", "grecaptcha.ready", "recaptcha-token"
        ]
    ],
    "hCaptcha": [
        re.compile(p, re.IGNORECASE) for p in [
            "hcaptcha", "assets.hcaptcha.com", "hcaptcha.com/1/api.js",
            "data-hcaptcha-sitekey", "js.stripe.com/v3/hcaptcha-invisible",
            "hcaptcha-invisible", "hcaptcha.execute"
        ]
    ],
    "Turnstile": [
        re.compile(p, re.IGNORECASE) for p in [
            "turnstile", "challenges.cloudflare.com", "cf-turnstile-response",
            "data-sitekey", "__cf_chl_", "cf_clearance"
        ]
    ],
    "Arkose Labs": [
        re.compile(p, re.IGNORECASE) for p in [
            "arkose-labs", "funcaptcha", "client-api.arkoselabs.com",
            "fc-token", "fc-widget", "arkose", "press and hold", "funcaptcha.com"
        ]
    ],
    "GeeTest": [
        re.compile(p, re.IGNORECASE) for p in [
            "geetest", "gt_captcha_obj", "gt.js", "geetest_challenge",
            "geetest_validate", "geetest_seccode"
        ]
    ],
    "BotDetect": [
        re.compile(p, re.IGNORECASE) for p in [
            "botdetectcaptcha", "BotDetect", "BDC_CaptchaImage", "CaptchaCodeTextBox"
        ]
    ],
    "KeyCAPTCHA": [
        re.compile(p, re.IGNORECASE) for p in [
            "keycaptcha", "kc_submit", "kc__widget", "s_kc_cid"
        ]
    ],
    "Anti Bot Detection": [
        re.compile(p, re.IGNORECASE) for p in [
            "fingerprintjs", "js.challenge", "checking your browser",
            "verify you are human", "please enable javascript and cookies",
            "sec-ch-ua-platform"
        ]
    ],
    "Captcha": [
        re.compile(p, re.IGNORECASE) for p in [
            "captcha-container", "captcha-box", "captcha-frame", "captcha_input",
            'id="captcha"', 'class="captcha"', "iframe.+?captcha",
            "data-captcha-sitekey"
        ]
    ]
}



THREE_D_SECURE_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'three_d_secure', r'3dsecure', r'acs', r'acs_url', r'acsurl', r'redirect',
    r'secure-auth', r'three_d_secure_usage', r'challenge', r'3ds', r'3ds1', r'3ds2', r'tds', r'tdsecure',
    r'3d-secure', r'three-d', r'3dcheck', r'3d-auth', r'three-ds',
    r'stripe\.com/3ds', r'm\.stripe\.network', r'hooks\.stripe\.com/3ds',
    r'paddle_frame', r'paddlejs', r'secure\.paddle\.com', r'buy\.paddle\.com',
    r'idcheck', r'garanti\.com\.tr', r'adyen\.com/hpp', r'adyen\.com/checkout',
    r'adyenpayments\.com/3ds', r'auth\.razorpay\.com', r'razorpay\.com/3ds',
    r'secure\.razorpay\.com', r'3ds\.braintreegateway\.com', r'verify\.3ds',
    r'checkout\.com/3ds', r'checkout\.com/challenge', r'3ds\.paypal\.com',
    r'authentication\.klarna\.com', r'secure\.klarna\.com/3ds'
]]


PLATFORM_KEYWORDS = {
    "woocommerce": [re.compile("woocommerce", re.IGNORECASE)],
    "shopify": [re.compile("shopify", re.IGNORECASE)],
    "magento": [re.compile("magento", re.IGNORECASE)],
    "bigcommerce": [re.compile("bigcommerce", re.IGNORECASE)],
    "prestashop": [re.compile("prestashop", re.IGNORECASE)],
    "opencart": [re.compile("opencart", re.IGNORECASE)],
    "wix": [re.compile("wix", re.IGNORECASE)],
    "squarespace": [re.compile("squarespace", re.IGNORECASE)],
}


GRAPHQL_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'/graphql', r'graphql\.js', r'graphql-endpoint', r'query \{', r'mutation \{'
]]

app = FastAPI()

class GatewayFinder:
    def __init__(self):
        self.seen_urls = set()
        self.session = tls_client.Session(client_identifier="chrome_120")
    async def crawl_urls(self, start_url: str, max_depth: int = 2) -> Set[str]:
        """Crawl the website for payment-related URLs from anchors, buttons, forms, and onclicks."""
        visited = set()
        to_visit = [(start_url, 0)]
        collected_urls = set()
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            
            while to_visit:
                current_url, depth = to_visit.pop(0)
                logger.info(f"[crawl_urls] Visiting: {current_url} at depth {depth}")
                if current_url in visited or depth > max_depth:
                    continue
                visited.add(current_url)
                try:
                    await page.goto(current_url, timeout=30000)
                    await asyncio.sleep(2)
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    anchors = await page.query_selector_all("a")
                    for a in anchors:
                        href = await a.get_attribute("href")
                        if href:
                            full_url = urljoin(current_url, href)
                            if self.is_relevant_url(full_url, start_url):
                                collected_urls.add(full_url)
                                to_visit.append((full_url, depth + 1))
                                logger.info(f"[crawl_urls] Queued for crawl: {full_url} (depth {depth + 1})")
                    forms = await page.query_selector_all("form")
                    for form in forms:
                        action = await form.get_attribute("action")
                        if action:
                            full_url = urljoin(current_url, action)
                            if self.is_relevant_url(full_url, start_url):
                                collected_urls.add(full_url)
                                to_visit.append((full_url, depth + 1))
                    buttons = await page.query_selector_all("button")
                    for btn in buttons:
                        onclick = await btn.get_attribute("onclick")
                        if onclick:
                            urls_in_js = self.extract_urls_from_js(onclick, current_url)
                            for u in urls_in_js:
                                if self.is_relevant_url(u, start_url):
                                    collected_urls.add(u)
                                    to_visit.append((u, depth + 1))
                    for a in anchors:
                        onclick = await a.get_attribute("onclick")
                        if onclick:
                            urls_in_js = self.extract_urls_from_js(onclick, current_url)
                            for u in urls_in_js:
                                if self.is_relevant_url(u, start_url):
                                    collected_urls.add(u)
                                    to_visit.append((u, depth + 1))
                except Exception as e:
                    logger.error(f"Error crawling {current_url}: {e}")
            await browser.close()
        logger.info(f"[crawl_urls] Found {len(collected_urls)} relevant URLs from {start_url}")
        return collected_urls.union({start_url})

    def is_relevant_url(self, url: str, base_url: str) -> bool:
        """Check if a URL is relevant based on payment indicators and filters."""
        if any(ext in url.lower() for ext in NON_HTML_EXTENSIONS):
            return False
        if any(ignore in url.lower() for ignore in IGNORE_IF_URL_CONTAINS):
            return False
        if any(regex.search(url) for regex in PAYMENT_INDICATOR_REGEX):
            return True
        return False
    def extract_urls_from_js(self, js_code: str, base_url: str) -> Set[str]:
        """Extract URLs from inline JS like onclick handlers."""
        urls = set()
        patterns = [
            r"['\"](\/[a-zA-Z0-9_\-\/\?\=\&\#]+)['\"]",
            r"['\"](https?:\/\/[^\s\"']+)['\"]"
        ]
        for pattern in patterns:
            for match in re.findall(pattern, js_code):
                full_url = urljoin(base_url, match)
                urls.add(full_url)
        return urls

    async def puppeteer_analyze(self, urls: List[str]) -> Dict:
        """Analyze URLs with Puppeteer for Shadow DOM, iframes, and JS."""
        results = {"gateways": set(), "3d_secure": False, "captcha": set()}
        browser = await launch(headless=True, args=['--no-sandbox'])
        page = await browser.new_page()
        
        for url in urls:
            try:
                await page.goto(url, timeout=30000)
                await asyncio.sleep(5)
                # Inspect Shadow DOM and iframes
                shadow_elements = await page.evaluate('''() => {
                    let results = [];
                    document.querySelectorAll('*').forEach(el => {
                        if (el.shadowRoot) results.push(el.shadowRoot.innerHTML);
                    });
                    return results;
                }''')
                iframe_content = await page.evaluate('''() => {
                    let results = [];
                    document.querySelectorAll('iframe').forEach(frame => {
                        try { results.push(frame.contentDocument.body.innerHTML); } catch {}
                    });
                    return results;
                }''')
                
                content = shadow_elements + iframe_content + [await page.content()]
                for gateway, patterns in GATEWAY_KEYWORDS.items():
                    if any(any(pattern.search(c) for pattern in patterns) for c in content):
                        results["gateways"].add(gateway)
                for captcha, patterns in CAPTCHA_PATTERNS.items():
                    if any(any(pattern.search(c) for pattern in patterns) for c in content):
                        results["captcha"].add(captcha)
                if any(any(pattern.search(c) for pattern in THREE_D_SECURE_KEYWORDS) for c in content):
                    results["3d_secure"] = True
            except Exception as e:
                logger.error(f"Puppeteer error on {url}: {e}")
        await browser.close()
        return results

    async def playwright_analyze(self, urls: List[str]) -> Dict:
        """Analyze URLs with Playwright for forms and JS rendering."""
        results = {"gateways": set(), "3d_secure": False, "captcha": set(), "platform": None}
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            for url in urls:
                try:
                    await page.goto(url, timeout=30000)
                    await asyncio.sleep(5)
                    content = await page.content()
                    if "cf-turnstile-response" in content or "challenge" in content.lower():
                        logger.warning(f"[playwright] Cloudflare challenge detected at {url}")
                    for gateway, patterns in GATEWAY_KEYWORDS.items():
                        if any(pattern.search(content) for pattern in patterns):
                            results["gateways"].add(gateway)
                    for captcha, patterns in CAPTCHA_PATTERNS.items():
                        if any(pattern.search(content) for pattern in patterns):
                            results["captcha"].add(captcha)
                    for platform, patterns in PLATFORM_KEYWORDS.items():
                        if any(pattern.search(content) for pattern in patterns):
                            results["platform"] = platform
                    if any(pattern.search(content) for pattern in THREE_D_SECURE_KEYWORDS):
                        results["3d_secure"] = True
                except Exception as e:
                    logger.error(f"Playwright error on {url}: {e}")
            await browser.close()
        return results

    async def selenium_wire_analyze(self, urls: List[str]) -> Dict:
        """Analyze network traffic with Selenium Wire."""
        results = {"gateways": set(), "3d_secure": False, "captcha": set(), "cloudflare": False}
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=options)
        
        for url in urls:
            try:
                driver.get(url)
                time.sleep(5)
                for request in driver.requests:
                    if any("cloudflare" or "cf-ray" in str(request).lower() for _ in [1]):
                        results["cloudflare"] = True
                    for gateway, patterns in GATEWAY_KEYWORDS.items():
                        if any(pattern.search(str(request)) for pattern in patterns):
                            results["gateways"].add(gateway)
                    for captcha, patterns in CAPTCHA_PATTERNS.items():
                        if any(pattern.search(str(request)) for pattern in patterns):
                            results["captcha"].add(captcha)
                    if any(pattern.search(str(request)) for pattern in THREE_D_SECURE_KEYWORDS):
                        results["3d_secure"] = True
            except Exception as e:
                logger.error(f"Selenium Wire error on {url}: {e}")
        driver.quit()
        return results

    async def analyze(self, url: str) -> Dict:
        """Main analysis function."""
        start_time = time.time()
        results = {
            "url": url,
            "payment_gateway": [],
            "3d_secure": "no",
            "captcha": [],
            "cloudflare": "not found",
            "platform": None,
            "graphql_found": "no",
            "time_taken": "0.00"
        }

        # Crawl URLs
        urls = await self.crawl_urls(url, max_depth=2)
        urls.add(url)  # Include initial URL

        # Run tools in parallel
        playwright_deep_task = self.playwright_analyze(urls)
        playwright_task = self.playwright_analyze(urls)
        selenium_task = self.selenium_wire_analyze(urls)
        playwright_result, playwright_deep_result, selenium_result = await asyncio.gather(
            playwright_task, playwright_deep_task, selenium_task, return_exceptions=True
        )

        # Aggregate results
        for result in [playwright_result, playwright_deep_result, selenium_result]:
            if isinstance(result, dict):
                results["payment_gateway"].extend(list(result.get("gateways", set())))
                if result.get("3d_secure", False):
                    results["3d_secure"] = "yes"
                results["captcha"].extend(list(result.get("captcha", set())))
                if result.get("cloudflare", False):
                    results["cloudflare"] = "found"
                if result.get("platform"):
                    results["platform"] = result["platform"]

        # Check for GraphQL
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            try:
                await page.goto(url, timeout=30000)
                content = await page.content()
                if any(pattern.search(content) for pattern in GRAPHQL_KEYWORDS):
                    results["graphql_found"] = "yes"
            except Exception as e:
                logger.error(f"GraphQL check error: {e}")
            await browser.close()

        results["payment_gateway"] = list(set(results["payment_gateway"]))
        results["captcha"] = list(set(results["captcha"]))
        results["time_taken"] = f"{time.time() - start_time:.2f}"
        return results

@app.get("/gateway/")
async def gateway_endpoint(url: HttpUrl):
    """API endpoint to analyze a website."""
    try:
        finder = GatewayFinder()
        result = await finder.analyze(str(url))
        return result
    except Exception as e:
        logger.error(f"API error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
