import asyncio
import re
import time
import logging
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional
from fastapi import FastAPI, HTTPException
from pydantic import HttpUrl
from playwright.async_api import async_playwright
from seleniumwire import webdriver
from bs4 import BeautifulSoup
import aiohttp
import tls_client
from uuid import uuid4
import threading
import random
from firebase_admin import messaging, credentials
import firebase_admin
import socket

# Initialize Firebase Admin SDK (replace with your credentials path)
try:
    cred = credentials.Certificate("path/to/firebase-credentials.json")
    firebase_admin.initialize_app(cred)
except Exception as e:
    logging.warning(f"Firebase initialization failed: {e}. FCM notifications may not work.")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Dictionaries
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
        # Additional terms
        "pay-with-card", "secure-pay", "order-confirmation", "payment-success", "pay-now-button"
    ]
]

NON_HTML_EXTENSIONS = [
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
    ".ico", ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".mp4", ".avi", ".mov",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".wav", ".flac"
]

IGNORE_IF_URL_CONTAINS = [
    # Common asset/content folders
    "wp-content", "wp-includes", "youtube.com", "www.youtube.com", "https://youtube.com",
    "https://www.youtube.com", "gstatic.com/instantbuy/svg/transparent_square.svg",
    "skin/frontend", "/assets/", "assets", "gstatic.com", ".svg", "transparent_square.svg",
    "cdn.cookielaw.org", "cookiebot.com", "clarity.ms", "sentry.io", "cdn.jsdelivr.net",
    "fonts.gstatic.com", "doubleclick.net", "segment.com", "matomo.org", "bam.nr-data.net",
    "/browser/vitals", "/themes/", "/static/", "/media/", "/images/", "/img/",
    "https://facebook.com", "youtubei/v1/log_event", "https://play.google.com",
    "google.com/log", "https://googlemanager.com", "consentcdn.cookiebot.com",
    "https://hb.imgix.net", "https://content-autofill.googleapis.com", "static.klaviyo.com",
    "https://www.google.com", "https://googleads.g.doubleclick.net",
    "https://www.googletagmanager.com", "googletagmanager.com", "https://www.googleadservices.com",
    "googleadservices.com", "https://fonts.googleapis.com", "fonts.googleapis.com",
    "http://clients2.google.com", "clients2.google.com", "https://analytics.google.com",
    "hanalytics.google.com",
    # Analytics & marketing scripts
    "googleapis", "gstatic", "googletagmanager", "google-analytics", "analytics",
    "facebook.net", "fbcdn", "pixel.", "tiktokcdn", "matomo", "segment.io",
    "clarity.ms", "mouseflow", "hotjar",
    # Fonts, icons, visual only
    "fonts.", "fontawesome", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".ico", ".svg",
    # CDN & framework scripts
    "cdn.jsdelivr.net", "cloudflareinsights.com", "cdnjs", "bootstrapcdn", "polyfill.io",
    "jsdelivr.net", "unpkg.com", "yastatic.net", "akamai", "fastly",
    # Media, tracking images
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".svg", ".ico",
    # Useless scripts/styles
    ".css", ".scss", ".less", ".map", ".js", "main.js", "bundle.js", "common.js",
    "theme.js", "style.css", "custom.css",
    # Other non-payment known paths
    "/favicon", "/robots.txt", "/sitemap", "/manifest", "/rss", "/feed", "/help",
    "/support", "/about", "/terms", "/privacy"
]

PAYMENT_GATEWAY = [
    'paypal.com', 'stripe.com', 'braintreegateway.com', 'adyen.com', 'authorize.net',
    'squareup.com', 'klarna.com', 'checkout.com', 'razorpay.com', 'paytm.in',
    'shopify.com', 'worldpay.com', '2co.com', 'amazon.com', 'apple.com', 'google.com',
    'mollie.com', 'opayo.eu', 'paddle.com', 'skrill.com', 'alipay.com', 'wepay.com'
]

NETWORK_PAYMENT_URL_KEYWORDS = [
    "/checkout", "/payment", "/pay", "/setup_intent", "/authorize_payment", "/intent",
    "/charge", "/authorize", "/submit_payment", "/create_order", "/payment_intent",
    "/process_payment", "/transaction", "/confirm_payment", "/capture", "/payment-method",
    "/billing", "/invoice", "/order/submit", "/tokenize", "/session", "/execute-payment",
    "/complete"
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
        r'api\.paypal\.com', r'paypal\.com', r'paypal-sdk\.com', r'paypal\.js', r'paypalobjects\.com',
        r'paypal_express_checkout', r'e\.PAYPAL_EXPRESS_CHECKOUT', r'paypal-button',
        r'paypal-checkout-sdk', r'paypal-sdk\.js', r'paypal-smart-button', r'paypal_express_checkout/api',
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
        r'squareup\.com', r'pci-connect.squareup.com', r'js\.squarecdn\.com', r'square\.js', r'data-square',
        r'square-payment-form', r'square-checkout-sdk', r'connect\.squareup\.com', r'square\.min\.js',
        r'squarecdn\.com', r'squareupsandbox\.com', r'sandbox\.web\.squarecdn\.com', r'square-payment-flow',
        r'square\.card', r'squareup\.com/payments', r'data-square-application-id', r'square\.createPayment'
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
        r'apple-pay\.js', r'data-apple-pay', r'apple-pay-button', r'apple-pay-checkout-sdk',
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
    ]],
    "skrill": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'skrill\.com', r'pay\.skrill\.com', r'skrill\.js', r'data-skrill', r'skrill-checkout'
    ]],
    "alipay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'alipay\.com', r'api\.alipay\.com', r'alipay\.js', r'data-alipay', r'alipay-checkout'
    ]],
    "wepay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'wepay\.com', r'api\.wepay\.com', r'wepay\.js', r'data-wepay', r'wepay-checkout'
    ]]
}

CAPTCHA_PATTERNS = {
    "reCaptcha": [re.compile(p, re.IGNORECASE) for p in [
        "g-recaptcha", "recaptcha/api.js", "data-sitekey", "nocaptcha",
        "recaptcha.net", "www.google.com/recaptcha", "grecaptcha.execute",
        "grecaptcha.render", "grecaptcha.ready", "recaptcha-token"
    ]],
    "hCaptcha": [re.compile(p, re.IGNORECASE) for p in [
        "hcaptcha", "assets.hcaptcha.com", "hcaptcha.com/1/api.js",
        "data-hcaptcha-sitekey", "js.stripe.com/v3/hcaptcha-invisible",
        "hcaptcha-invisible", "hcaptcha.execute"
    ]],
    "Turnstile": [re.compile(p, re.IGNORECASE) for p in [
        "turnstile", "challenges.cloudflare.com", "cf-turnstile-response",
        "data-sitekey", "__cf_chl_", "cf_clearance"
    ]],
    "Arkose Labs": [re.compile(p, re.IGNORECASE) for p in [
        "arkose-labs", "funcaptcha", "client-api.arkoselabs.com",
        "fc-token", "fc-widget", "arkose", "press and hold", "funcaptcha.com"
    ]],
    "GeeTest": [re.compile(p, re.IGNORECASE) for p in [
        "geetest", "gt_captcha_obj", "gt.js", "geetest_challenge",
        "geetest_validate", "geetest_seccode"
    ]],
    "BotDetect": [re.compile(p, re.IGNORECASE) for p in [
        "botdetectcaptcha", "BotDetect", "BDC_CaptchaImage", "CaptchaCodeTextBox"
    ]],
    "KeyCAPTCHA": [re.compile(p, re.IGNORECASE) for p in [
        "keycaptcha", "kc_submit", "kc__widget", "s_kc_cid"
    ]],
    "Anti Bot Detection": [re.compile(p, re.IGNORECASE) for p in [
        "fingerprintjs", "js.challenge", "checking your browser",
        "verify you are human", "please enable javascript and cookies",
        "sec-ch-ua-platform"
    ]],
    "Captcha": [re.compile(p, re.IGNORECASE) for p in [
        "captcha-container", "captcha-box", "captcha-frame", "captcha_input",
        'id="captcha"', 'class="captcha"', "iframe.+?captcha",
        "data-captcha-sitekey"
    ]]
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
    r'authentication\.klarna\.com', r'secure\.klarna\.com/3ds',
    r'3ds2-auth', r'3ds2-challenge', r'3ds2-redirect', r'acs2', r'3ds2\.com'
]]

PLATFORM_KEYWORDS = {
    "woocommerce": [re.compile("woocommerce", re.IGNORECASE)],
    "shopify": [re.compile("shopify", re.IGNORECASE)],
    "magento": [re.compile("magento", re.IGNORECASE)],
    "bigcommerce": [re.compile("bigcommerce", re.IGNORECASE)],
    "prestashop": [re.compile("prestashop", re.IGNORECASE)],
    "opencart": [re.compile("opencart", re.IGNORECASE)],
    "wix": [re.compile("wix", re.IGNORECASE)],
    "squarespace": [re.compile("squarespace", re.IGNORECASE)]
}

GRAPHQL_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'/graphql', r'graphql\.js', r'graphql-endpoint', r'query \{', r'mutation \{'
]]

CARD_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'visa', r'mastercard', r'amex', r'discover', r'diners', r'jcb', r'unionpay',
    r'maestro', r'rupay', r'cartasi', r'hipercard'
]]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Mobile Safari/537.36"
]

app = FastAPI()
jobs = {}

class GatewayFinder:
    def __init__(self):
        self.seen_urls = set()
        self.session = tls_client.Session(client_identifier="chrome_120")
        self.detected_gateways = []

    def is_relevant_url(self, url: str, base_url: str) -> bool:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Skip non-HTTP/HTTPS
        if parsed.scheme not in ("http", "https"):
            return False
        
        # Skip non-HTML resources
        if any(path.endswith(ext) for ext in NON_HTML_EXTENSIONS):
            return False
        
        # Skip ignored domains or paths
        if any(ignore in url.lower() for ignore in IGNORE_IF_URL_CONTAINS):
            return False
        
        # Allow same domain or trusted payment gateways
        base_domain = urlparse(base_url).netloc.lower()
        if not (domain == base_domain or domain.endswith('.' + base_domain)) and not any(gw in domain for gw in PAYMENT_GATEWAY):
            return False
        
        # Prioritize payment-related URLs
        if any(regex.search(url) for regex in PAYMENT_INDICATOR_REGEX):
            return True
        
        return False

    async def extract_deep_content(self, page):
        html_chunks = []
        
        # Main page content
        try:
            html_chunks.append(await page.content())
        except Exception as e:
            logger.warning(f"Failed to get main page HTML: {e}")
        
        # Iframe content
        try:
            iframes = await page.query_selector_all('iframe')
            for iframe in iframes:
                try:
                    frame = await iframe.content_frame()
                    if frame:
                        html_chunks.append(await frame.content())
                except Exception as e:
                    logger.info(f"Failed to access iframe: {e}")
        except Exception as e:
            logger.warning(f"Error iterating iframes: {e}")
        
        # Shadow DOM content
        try:
            shadow_content = await page.evaluate('''() => {
                let results = [];
                document.querySelectorAll('*').forEach(el => {
                    if (el.shadowRoot) results.push(el.shadowRoot.innerHTML);
                });
                return results;
            }''')
            html_chunks.extend(shadow_content or [])
        except Exception as e:
            logger.warning(f"Failed to read Shadow DOMs: {e}")
        
        return html_chunks

    async def crawl_urls(self, start_url: str, max_depth: int = 2, visited: set = None) -> Set[str]:
        if visited is None:
            visited = set()
        urls = set()
        if max_depth < 1 or start_url in visited:
            return urls
        visited.add(start_url)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled"])
            page = await browser.new_page(user_agent=random.choice(USER_AGENTS))
            try:
                await page.goto(start_url, timeout=30000)
                await asyncio.sleep(5)
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")

                # Extract links from <a> tags
                links = await page.query_selector_all('a')
                for link in links:
                    href = await link.get_attribute('href')
                    full_url = urljoin(start_url, href)
                    if self.is_relevant_url(full_url, start_url):
                        urls.add(full_url)

                # Extract links from buttons and forms
                soup = BeautifulSoup(await page.content(), "lxml")
                for btn in soup.find_all("button"):
                    onclick = btn.get("onclick", "")
                    match = re.search(r"""window\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""", onclick)
                    if match:
                        full_url = urljoin(start_url, match.group(1))
                        if self.is_relevant_url(full_url, start_url):
                            urls.add(full_url)
                for form in soup.find_all("form", action=True):
                    full_url = urljoin(start_url, form["action"])
                    if self.is_relevant_url(full_url, start_url):
                        urls.add(full_url)

                # Recursively crawl sub-links
                if max_depth > 1:
                    tasks = [self.crawl_urls(url, max_depth - 1, visited) for url in urls]
                    sub_urls = await asyncio.gather(*tasks, return_exceptions=True)
                    for sub_url_set in sub_urls:
                        if isinstance(sub_url_set, set):
                            urls.update(sub_url_set)

            except Exception as e:
                logger.error(f"Error crawling {start_url}: {e}")
            finally:
                await browser.close()
        return urls

    async def playwright_analyze(self, urls: List[str]) -> Dict:
        results = {
            "gateways": set(), "3d_secure": set(), "captcha": set(),
            "platform": None, "cards": set(), "graphql": "False"
        }
        clickable_keywords = ["buy", "subscribe", "checkout", "payment", "plan", "join", "start"]
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled"])
            page = await browser.new_page(user_agent=random.choice(USER_AGENTS))
            
            for url in urls:
                try:
                    await page.goto(url, timeout=30000)
                    await asyncio.sleep(5)
                    
                    # Click payment-related buttons or links
                    elements = await page.query_selector_all('button, a')
                    for element in elements:
                        text = (await element.inner_text()).lower().strip()
                        if any(kw in text for kw in clickable_keywords):
                            try:
                                await element.click()
                                await asyncio.sleep(3)
                            except Exception as e:
                                logger.info(f"Failed to click element at {url}: {e}")

                    contents = await self.extract_deep_content(page)
                    
                    for content in contents:
                        content_lower = content.lower()
                        # Payment gateways
                        for gateway, patterns in GATEWAY_KEYWORDS.items():
                            matches = [p.pattern for p in patterns if p.search(content_lower)]
                            gateway_name = gateway.capitalize()
                            if "shopify" in url.lower() and gateway.lower() == "stripe":
                                continue
                            if len(matches) >= 2 and gateway_name not in self.detected_gateways:
                                results["gateways"].add(gateway_name)
                                self.detected_gateways.append(gateway_name)
                            elif len(matches) == 1 and gateway_name not in self.detected_gateways:
                                low_cred = f"{gateway_name} Low Credibility"
                                results["gateways"].add(low_cred)
                                self.detected_gateways.append(low_cred)
                        
                        # 3D Secure
                        for tds_pattern in THREE_D_SECURE_KEYWORDS:
                            if tds_pattern.search(content_lower):
                                results["3d_secure"].add("ENABLED")
                        
                        # Captcha
                        for category, patterns in CAPTCHA_PATTERNS.items():
                            if any(p.search(content_lower) for p in patterns):
                                results["captcha"].add(f"{category} Found")
                        
                        # Platforms
                        for keyword, name in PLATFORM_KEYWORDS.items():
                            if any(p.search(content_lower) for p in name):
                                results["platform"] = name
                        
                        # Cards
                        for card_pattern in CARD_KEYWORDS:
                            if card_pattern.search(content_lower):
                                card_name = card_pattern.pattern.lstrip(r'\b').rstrip(r'\b').capitalize()
                                results["cards"].add(card_name)
                        
                        # GraphQL
                        if any(p.search(content_lower) for p in GRAPHQL_KEYWORDS):
                            results["graphql"] = "True"
                except Exception as e:
                    logger.error(f"Playwright error on {url}: {e}")
            await browser.close()
        return results

    async def selenium_wire_analyze(self, urls: List[str]) -> Dict:
        results = {
            "gateways": set(), "3d_secure": set(), "captcha": set(),
            "cloudflare": False, "cards": set(), "graphql": "False"
        }
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument(f"user-agent={random.choice(USER_AGENTS)}")
        driver = webdriver.Chrome(options=options)
        
        for url in urls:
            try:
                driver.get(url)
                driver.execute_script("""
                    window.__capturedFetches = [];
                    const originalFetch = window.fetch;
                    window.fetch = async function(...args) {
                        const response = await originalFetch(...args);
                        const clone = response.clone();
                        try {
                            const bodyText = await clone.text();
                            window.__capturedFetches.push({
                                url: args[0],
                                method: (args[1] && args[1].method) || 'GET',
                                body: (args[1] && args[1].body) || '',
                                response: bodyText
                            });
                        } catch (e) {}
                        return response;
                    };
                """)
                time.sleep(5)
                
                # Collect fetch logs
                fetch_logs = driver.execute_script("return window.__capturedFetches || []")
                for entry in fetch_logs:
                    combined = f"{entry['url']} {entry['body']} {entry['response']}".lower()
                    for gateway, patterns in GATEWAY_KEYWORDS.items():
                        if any(p.search(combined) for p in patterns):
                            gateway_name = gateway.capitalize()
                            if "shopify" in url.lower() and gateway.lower() == "stripe":
                                continue
                            if len([p for p in patterns if p.search(combined)]) >= 2 and gateway_name not in self.detected_gateways:
                                results["gateways"].add(gateway_name)
                                self.detected_gateways.append(gateway_name)
                            elif len([p for p in patterns if p.search(combined)]) == 1 and gateway_name not in self.detected_gateways:
                                low_cred = f"{gateway_name} Low Credibility"
                                results["gateways"].add(low_cred)
                                self.detected_gateways.append(low_cred)
                    for tds_pattern in THREE_D_SECURE_KEYWORDS:
                        if tds_pattern.search(combined):
                            results["3d_secure"].add("ENABLED")
                    for category, patterns in CAPTCHA_PATTERNS.items():
                        if any(p.search(combined) for p in patterns):
                            results["captcha"].add(f"{category} Found")
                    for card_pattern in CARD_KEYWORDS:
                        if card_pattern.search(combined):
                            card_name = card_pattern.pattern.lstrip(r'\b').rstrip(r'\b').capitalize()
                            results["cards"].add(card_name)
                    if any(p.search(combined) for p in GRAPHQL_KEYWORDS):
                        results["graphql"] = "True"
                    if any(kw in entry['url'].lower() for kw in NETWORK_PAYMENT_URL_KEYWORDS):
                        logger.info(f"Payment-related URL detected: {entry['url']}")
                        for gateway, patterns in GATEWAY_KEYWORDS.items():
                            if any(p.search(combined) for p in patterns):
                                gateway_name = gateway.capitalize()
                                if "shopify" in url.lower() and gateway.lower() == "stripe":
                                    continue
                                if len([p for p in patterns if p.search(combined)]) >= 2 and gateway_name not in self.detected_gateways:
                                    results["gateways"].add(gateway_name)
                                    self.detected_gateways.append(gateway_name)
                                elif len([p for p in patterns if p.search(combined)]) == 1 and gateway_name not in self.detected_gateways:
                                    low_cred = f"{gateway_name} Low Credibility"
                                    results["gateways"].add(low_cred)
                                    self.detected_gateways.append(low_cred)
                
                for request in driver.requests:
                    if not request.response:
                        continue
                    combined = f"{request.url} {request.body.decode('utf-8', errors='ignore') if request.body else ''}".lower()
                    if any(s in combined for s in ["cloudflare", "cf-ray", "cf_clearance"]):
                        results["cloudflare"] = True
                    for gateway, patterns in GATEWAY_KEYWORDS.items():
                        if any(p.search(combined) for p in patterns):
                            gateway_name = gateway.capitalize()
                            if "shopify" in url.lower() and gateway.lower() == "stripe":
                                continue
                            if len([p for p in patterns if p.search(combined)]) >= 2 and gateway_name not in self.detected_gateways:
                                results["gateways"].add(gateway_name)
                                self.detected_gateways.append(gateway_name)
                            elif len([p for p in patterns if p.search(combined)]) == 1 and gateway_name not in self.detected_gateways:
                                low_cred = f"{gateway_name} Low Credibility"
                                results["gateways"].add(low_cred)
                                self.detected_gateways.append(low_cred)
                    for tds_pattern in THREE_D_SECURE_KEYWORDS:
                        if tds_pattern.search(combined):
                            results["3d_secure"].add("ENABLED")
                    for category, patterns in CAPTCHA_PATTERNS.items():
                        if any(p.search(combined) for p in patterns):
                            results["captcha"].add(f"{category} Found")
                    for card_pattern in CARD_KEYWORDS:
                        if card_pattern.search(combined):
                            card_name = card_pattern.pattern.lstrip(r'\b').rstrip(r'\b').capitalize()
                            results["cards"].add(card_name)
                    if any(p.search(combined) for p in GRAPHQL_KEYWORDS):
                        results["graphql"] = "True"
            except Exception as e:
                logger.error(f"Selenium Wire error on {url}: {e}")
        driver.quit()
        return results

    async def analyze(self, url: str, timeout: Optional[int] = None) -> Dict:
        start_time = time.time()
        results = {
            "url": url,
            "payment_gateway": [],
            "3d_secure": "no",
            "captcha": [],
            "cloudflare": "not found",
            "platform": None,
            "graphql_found": "no",
            "cards": [],
            "time_taken": "0.00",
            "country": "Unknown",
            "ip": "Unknown"
        }

        # Get IP and country
        try:
            base_domain = urlparse(url).netloc
            results["ip"] = socket.gethostbyname(base_domain)
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://ipapi.co/{results['ip']}/country_name/", timeout=5) as response:
                    if response.status == 200:
                        results["country"] = (await response.text()).strip()
        except Exception as e:
            logger.warning(f"Failed to get IP/country: {e}")

        # Crawl URLs
        urls = await self.crawl_urls(url, max_depth=2)
        urls.add(url)

        if timeout and time.time() - start_time > timeout:
            return {"success": False, "error": "Scan timed out"}

        # Run analyses
        playwright_result, selenium_result = await asyncio.gather(
            self.playwright_analyze(urls),
            self.selenium_wire_analyze(urls),
            return_exceptions=True
        )

        # Aggregate results
        for result in [playwright_result, selenium_result]:
            if isinstance(result, dict):
                results["payment_gateway"].extend(list(result.get("gateways", set())))
                if result.get("3d_secure"):
                    results["3d_secure"] = "yes"
                results["captcha"].extend(list(result.get("captcha", set())))
                if result.get("cloudflare", False):
                    results["cloudflare"] = "found"
                if result.get("platform"):
                    results["platform"] = result["platform"]
                if result.get("graphql") == "True":
                    results["graphql_found"] = "yes"
                results["cards"].extend(list(result.get("cards", set())))

        results["payment_gateway"] = sorted(list(set(results["payment_gateway"])))
        results["captcha"] = sorted(list(set(results["captcha"])))
        results["cards"] = sorted(list(set(results["cards"])))
        results["time_taken"] = f"{time.time() - start_time:.2f}"
        return results

async def background_scan(url: str, job_id: str, timeout: Optional[int] = None, fcm_token: Optional[str] = None):
    try:
        finder = GatewayFinder()
        result = await finder.analyze(str(url), timeout)
        jobs[job_id] = {"status": "done", "result": {"success": True, "data": result}}
        if fcm_token:
            try:
                message = messaging.Message(
                    notification=messaging.Notification(
                        title="Scan Completed",
                        body=f"Scan for {url} completed. Job ID: {job_id}"
                    ),
                    token=fcm_token
                )
                messaging.send(message)
            except Exception as e:
                logger.error(f"FCM notification failed: {e}")
    except Exception as e:
        jobs[job_id] = {"status": "done", "result": {"success": False, "error": f"Background task error: {str(e)}"}}
        if fcm_token:
            try:
                message = messaging.Message(
                    notification=messaging.Notification(
                        title="Scan Failed",
                        body=f"Scan for {url} failed: {str(e)}"
                    ),
                    token=fcm_token
                )
                messaging.send(message)
            except Exception as e:
                logger.error(f"FCM notification failed: {e}")

@app.get("/gateway/")
async def gateway_endpoint(url: HttpUrl, timeout: Optional[int] = None, fcm_token: Optional[str] = None):
    """API endpoint to analyze a website."""
    try:
        job_id = str(uuid4())
        jobs[job_id] = {"status": "pending", "result": None}
        threading.Thread(target=lambda: asyncio.run(background_scan(str(url), job_id, timeout, fcm_token))).start()
        return {"job_id": job_id, "message": "Scan started"}
    except Exception as e:
        logger.error(f"API error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/gateway/results/{job_id}")
async def get_scan_result(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job ID not found")
    if jobs[job_id]["status"] != "done":
        return {"status": "pending"}
    return {"status": "done", "result": jobs[job_id]["result"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
