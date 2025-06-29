import asyncio
import json
import re
import time
from typing import List, Dict
from urllib.parse import urljoin, urlparse
import aiohttp
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
import subprocess
import requests
import regex
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

# Keyword dictionaries
GATEWAY_KEYWORDS = {
    "stripe": [r"js\.stripe\.com", r"api\.stripe\.com", r"stripe-checkout\.js", r"payment_intent"],
    "paypal": [r"paypal\.com", r"paypalobjects\.com", r"paypal-button"],
    "braintree": [r"braintreegateway\.com", r"braintree-api\.com"],
    "square": [r"squareup\.com", r"square\.cdn"],
}

CAPTCHA_PATTERNS = {
    "reCaptcha": [r"recaptcha/api\.js", r"g-recaptcha", r"grecaptcha\.render"],
    "hCaptcha": [r"hcaptcha\.com", r"hcaptcha-script"],
    "geetest": [r"gt_captcha_obj"],
}

THREE_D_SECURE_KEYWORDS = [r"3ds2", r"acs", r"three_d_secure"]

PLATFORM_KEYWORDS = {
    "shopify": r"shopify",
    "woocommerce": r"woocommerce",
    "magento": r"magento",
}

IGNORE_URL_PATTERNS = [
    r"\.(jpg|jpeg|png|css|ico|woff|woff2|svg|js|gif|pdf)$",
    r"(wp-content|wp-includes|/assets/|/static/|/media/|facebook\.com|google\.com|fonts\.googleapis\.com|analytics)"
]

# FastAPI app
app = FastAPI()

# Configuration (replace with your ScrapFly API key)
SCRAPFLY_API_KEY = "your_scrapfly_api_key_here"
PUPPETEER_SCRIPT = """
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());

async function detect(url) {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 720 });
    
    try {
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
        await new Promise(resolve => setTimeout(resolve, 5000));
        await page.evaluate(() => window.scrollBy(0, window.innerHeight));
        
        const results = {
            forms: await page.$$eval('form', forms => forms.map(f => f.outerHTML)),
            scripts: await page.$$eval('script', scripts => scripts.map(s => s.src || s.innerHTML)),
            buttons: await page.$$eval('button', buttons => buttons.map(b => b.textContent)),
            iframes: await page.$$eval('iframe', iframes => iframes.map(i => i.src)),
            shadow_dom: await page.evaluate(() => {
                const shadows = [];
                document.querySelectorAll('*').forEach(el => {
                    if (el.shadowRoot) shadows.push(el.shadowRoot.innerHTML);
                });
                return shadows;
            })
        };
        await browser.close();
        return results;
    } catch (e) {
        await browser.close();
        return { error: e.message };
    }
}

(async () => {
    console.log(JSON.stringify(await detect(process.argv[2])));
})();
"""

# Write Puppeteer script to temporary file
with open("/tmp/detect.js", "w") as f:
    f.write(PUPPETEER_SCRIPT)

async def extract_valid_payment_urls(base_url: str) -> List[str]:
    """Extract payment-related URLs from the website up to depth 2."""
    valid_urls = set([base_url])
    visited = set()
    depth = 0
    
    async with aiohttp.ClientSession() as session:
        while depth < 2 and valid_urls:
            current_urls = list(valid_urls)
            valid_urls.clear()
            
            for url in current_urls:
                if url in visited:
                    continue
                visited.add(url)
                
                try:
                    async with session.get(url, timeout=30) as response:
                        if response.status != 200:
                            continue
                        html = await response.text()
                        soup = BeautifulSoup(html, 'lxml')
                        
                        # Extract all links
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            absolute_url = urljoin(url, href)
                            
                            # Skip if URL matches ignore patterns
                            if any(regex.search(pattern, absolute_url) for pattern in IGNORE_URL_PATTERNS):
                                continue
                            
                            # Check for payment-related keywords
                            if any(keyword in absolute_url.lower() for keyword in ['cart', 'checkout', 'pay', 'buy', 'order', 'billing']):
                                valid_urls.add(absolute_url)
                except Exception:
                    continue
            
            depth += 1
    
    return list(valid_urls)

async def scrapfly_fetch(url: str) -> Dict:
    """Fetch and analyze page using ScrapFly API."""
    try:
        async with aiohttp.ClientSession() as session:
            payload = {
                "key": SCRAPFLY_API_KEY,
                "url": url,
                "render_js": True,
                "asp": True,  # Anti-scraping protection
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            }
            async with session.post("https://api.scrapfly.io/scrape", json=payload) as response:
                if response.status != 200:
                    return {}
                result = await response.json()
                html = result['result']['content']
                
                soup = BeautifulSoup(html, 'lxml')
                return {
                    "html": html,
                    "forms": [str(form) for form in soup.find_all('form')],
                    "scripts": [script.get('src') or str(script) for script in soup.find_all('script')],
                    "meta": [meta.get('content') for meta in soup.find_all('meta') if meta.get('content')]
                }
    except Exception as e:
        return {"error": str(e)}

def selenium_wire_fetch(url: str) -> Dict:
    """Fetch and analyze network traffic using Selenium Wire."""
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    
    try:
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(30)
        driver.get(url)
        time.sleep(5)  # Mimic human behavior
        
        # Capture network requests
        requests = []
        for request in driver.requests:
            if request.response and request.url:
                requests.append({
                    "url": request.url,
                    "status": request.response.status_code,
                    "headers": dict(request.response.headers)
                })
        
        driver.quit()
        return {"requests": requests}
    except Exception as e:
        if 'driver' in locals():
            driver.quit()
        return {"error": str(e)}

def run_puppeteer(url: str) -> Dict:
    """Run Puppeteer script to analyze page."""
    try:
        result = subprocess.run(
            ["node", "/tmp/detect.js", url],
            capture_output=True,
            text=True,
            timeout=30
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}

def analyze_results(scrapfly_data: Dict, puppeteer_data: Dict, selenium_data: Dict) -> Dict:
    """Analyze combined results from all tools."""
    results = {
        "payment_gateway": [],
        "3d_enabled": False,
        "captcha": [],
        "cloudflare": False,
        "platform": None,
        "graphql_found": False
    }
    
    # Analyze ScrapFly data
    for gateway, patterns in GATEWAY_KEYWORDS.items():
        for data in [scrapfly_data.get('html', ''), *scrapfly_data.get('scripts', []), *scrapfly_data.get('forms', [])]:
            if any(regex.search(pattern, data, re.IGNORECASE) for pattern in patterns):
                if gateway not in results["payment_gateway"]:
                    results["payment_gateway"].append(gateway)
    
    # Analyze Puppeteer data
    for data in [puppeteer_data.get('scripts', []), puppeteer_data.get('forms', []), puppeteer_data.get('shadow_dom', [])]:
        for gateway, patterns in GATEWAY_KEYWORDS.items():
            if any(regex.search(pattern, str(data), re.IGNORECASE) for pattern in patterns):
                if gateway not in results["payment_gateway"]:
                    results["payment_gateway"].append(gateway)
    
    # Analyze Selenium data
    for request in selenium_data.get('requests', []):
        url = request.get('url', '')
        if 'cloudflare' in url.lower():
            results['cloudflare'] = True
        for gateway, patterns in GATEWAY_KEYWORDS.items():
            if any(regex.search(pattern, url, re.IGNORECASE) for pattern in patterns):
                if gateway not in results["payment_gateway"]:
                    results["payment_gateway"].append(gateway)
        for captcha, patterns in CAPTCHA_PATTERNS.items():
            if any(regex.search(pattern, url, re.IGNORECASE) for pattern in patterns):
                if captcha not in results["captcha"]:
                    results["captcha"].append(captcha)
        if any(regex.search(pattern, url, re.IGNORECASE) for pattern in THREE_D_SECURE_KEYWORDS):
            results["3d_enabled"] = True
    
    # Platform detection
    for platform, pattern in PLATFORM_KEYWORDS.items():
        if any(regex.search(pattern, str(data), re.IGNORECASE) for data in [scrapfly_data.get('html', ''), *puppeteer_data.get('scripts', [])]):
            results["platform"] = platform
    
    # GraphQL detection
    if any('graphql' in str(data).lower() for data in [scrapfly_data.get('html', ''), *selenium_data.get('requests', [])]):
        results["graphql_found"] = True
    
    return results

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    # Startup
    yield
    # Shutdown
    pass

app = FastAPI(lifespan=lifespan)

@app.get("/gateway/")
async def detect_gateway(url: str):
    """Main API endpoint to detect payment gateways and technologies."""
    start_time = time.time()
    
    if not url.startswith(('http://', 'https://')):
        raise HTTPException(status_code=400, detail="Invalid URL")
    
    # Extract payment-related URLs
    payment_urls = await extract_valid_payment_urls(url)
    
    results = {
        "url": url,
        "payment_gateway": [],
        "3d_enabled": False,
        "captcha": [],
        "cloudflare": False,
        "platform": None,
        "graphql_found": False,
        "time_taken": "0.00s"
    }
    
    # Run tools in parallel with retries
    with ThreadPoolExecutor(max_workers=3) as executor:
        for payment_url in payment_urls[:5]:  # Limit to 5 URLs to avoid excessive processing
            for attempt in range(2):  # Try twice
                try:
                    # Run all tools concurrently
                    scrapfly_task = asyncio.create_task(scrapfly_fetch(payment_url))
                    puppeteer_task = executor.submit(run_puppeteer, payment_url)
                    selenium_task = executor.submit(selenium_wire_fetch, payment_url)
                    
                    # Gather results
                    scrapfly_result = await scrapfly_task
                    puppeteer_result = puppeteer_task.result()
                    selenium_result = selenium_task.result()
                    
                    # Analyze results
                    partial_results = analyze_results(scrapfly_result, puppeteer_result, selenium_result)
                    
                    # Merge results
                    results["payment_gateway"].extend([g for g in partial_results["payment_gateway"] if g not in results["payment_gateway"]])
                    results["captcha"].extend([c for c in partial_results["captcha"] if c not in results["captcha"]])
                    results["3d_enabled"] = results["3d_enabled"] or partial_results["3d_enabled"]
                    results["cloudflare"] = results["cloudflare"] or partial_results["cloudflare"]
                    results["graphql_found"] = results["graphql_found"] or partial_results["graphql_found"]
                    if partial_results["platform"]:
                        results["platform"] = partial_results["platform"]
                    
                    break  # Success, move to next URL
                except Exception as e:
                    if attempt == 1:  # Last attempt failed
                        continue
                    await asyncio.sleep(1)  # Wait before retry
    
    results["time_taken"] = f"{time.time() - start_time:.2f}s"
    return results
