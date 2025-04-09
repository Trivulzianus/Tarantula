"""
Combined Web Crawler for Attack Surface Mapping

This script integrates both a simple HTML parser-based crawler and a Selenium-based crawler.
It accepts a target domain as a command-line argument, runs both crawlers sequentially,
merges their findings, and outputs a combined sitemap in JSON format.

Usage:
    python combined_crawler.py https://example.com
"""

import argparse
import json
import logging
import os
import random
import re
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin, urldefrag

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    WebDriverException,
)
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from queue import Queue, Empty


# ---------------------------- Configuration ---------------------------- #

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# ---------------------------- SimpleCrawler ---------------------------- #



class SimpleCrawler:
    """
    A simple web crawler that parses static HTML content to extract endpoints, parameters, and forms.
    """

    def __init__(self, target_domain, max_depth=10, timeout_minutes=5):
        self.target_domain = target_domain.lower().strip()
        self.max_depth = max_depth
        self.timeout = timeout_minutes * 60  # seconds
        self.results = {"domains": {}}
        self.visited = set()
        self.lock = threading.Lock()
        self.start_time = time.time()

        # Initialize a requests session with consistent headers
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AttackSurfaceCrawler/1.0",  # Fixed User-Agent as per requirements
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
        })

        # Initialize a queue for URLs to crawl
        self.url_queue = Queue()
    
    def crawl(self):
        """
        Starts the crawling process from the seed URL.
        """
        seed_url = f"https://{self.target_domain}"
        logging.info(f"SimpleCrawler: Starting crawl at {seed_url}")
        self.url_queue.put((seed_url, 0))  # Each item is a tuple (URL, depth)
        self.visited.add(self.normalize_url(seed_url))

        # Start ThreadPoolExecutor with fixed number of workers
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Schedule worker threads
            futures = [executor.submit(self.worker) for _ in range(10)]
            
            # Wait for the queue to be empty or timeout
            start_time = time.time()
            while True:
                current_time = time.time()
                elapsed_time = current_time - self.start_time
                if elapsed_time > self.timeout:
                    logging.info("SimpleCrawler: Crawling timed out.")
                    break
                if self.url_queue.empty():
                    # Check if all tasks are done
                    if all(f.done() for f in futures):
                        break
                time.sleep(1)  # Prevent busy waiting

            # Wait for all workers to finish
            self.url_queue.join()
        
        self.save_results()

    def worker(self):
        """
        Worker function to process URLs from the queue.
        """
        urls_per_depth = {}  # Track number of URLs processed at each depth

        while True:
            try:
                url, depth = self.url_queue.get(timeout=3)  # Wait for 3 seconds
            except Empty:
                # If no new URLs have been added for 3 seconds, exit
                return

            # Check if we've reached the URL limit for this depth
            with self.lock:
                if depth not in urls_per_depth:
                    urls_per_depth[depth] = 0
                if urls_per_depth[depth] >= 10:  # Max 10 URLs per depth
                    self.url_queue.task_done()
                    continue
                urls_per_depth[depth] += 1

            if time.time() - self.start_time > self.timeout:
                logging.info("SimpleCrawler: Crawling timed out.")
                self.url_queue.task_done()
                return

            if depth > self.max_depth:
                logging.debug(f"SimpleCrawler: Max depth {self.max_depth} reached at {url}")
                self.url_queue.task_done()
                continue

            logging.info(f"SimpleCrawler: Crawling URL: {url} at depth {depth}")
            try:
                response = self.session.get(url, timeout=15, allow_redirects=True)
                if response.status_code >= 400:
                    logging.warning(f"SimpleCrawler: Received status code {response.status_code} for URL: {url}")
                    self.url_queue.task_done()
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.lower()
                path = parsed_url.path or "/"

                with self.lock:
                    if domain not in self.results["domains"]:
                        self.results["domains"][domain] = {"endpoints": {}}
                    if path not in self.results["domains"][domain]["endpoints"]:
                        self.results["domains"][domain]["endpoints"][path] = {
                            "GET": {"available": True, "parameters": []},
                            "POST": {"available": False, "parameters": [], "forms": []},
                            "all_forms": []
                        }

                # Extract GET parameters from URL
                query = parsed_url.query
                if query:
                    params = [param.split('=')[0] for param in query.split('&') if param]
                    with self.lock:
                        existing_params = self.results["domains"][domain]["endpoints"][path]["GET"]["parameters"]
                        for param in params:
                            if param not in existing_params:
                                existing_params.append(param)
                                logging.debug(f"SimpleCrawler: Added GET parameter: {param}")

                # Extract forms
                forms = soup.find_all('form')
                for form in forms:
                    action = form.get('action') or url
                    method = form.get('method', 'GET').upper()
                    inputs = []
                    for input_elem in form.find_all(['input', 'textarea', 'select']):
                        name = input_elem.get('name', '')
                        input_type = input_elem.get('type', input_elem.name)
                        required = input_elem.has_attr('required')
                        inputs.append({
                            "name": name,
                            "type": input_type,
                            "required": required
                        })
                    form_data = {
                        "action": urljoin(url, action),
                        "method": method,
                        "inputs": inputs
                    }

                    with self.lock:
                        form_path = urlparse(form_data["action"]).path or "/"
                        if form_path not in self.results["domains"][domain]["endpoints"]:
                            self.results["domains"][domain]["endpoints"][form_path] = {
                                "GET": {"available": False, "parameters": []},
                                "POST": {"available": False, "parameters": [], "forms": []},
                                "all_forms": []
                            }
                        endpoint = self.results["domains"][domain]["endpoints"][form_path]
                        if method == "POST":
                            endpoint["POST"]["available"] = True
                            if form_data not in endpoint["POST"]["forms"]:
                                endpoint["POST"]["forms"].append(form_data)
                        elif method == "GET":
                            endpoint["GET"]["available"] = True
                            # Extract GET parameters from form inputs
                            form_inputs = [
                                input_elem.get('name') 
                                for input_elem in form.find_all(['input', 'textarea', 'select']) 
                                if input_elem.get('name')
                            ]
                            
                            for param in form_inputs:
                                if param not in endpoint["GET"]["parameters"]:
                                    endpoint["GET"]["parameters"].append(param)
                                    logging.debug(f"SimpleCrawler: Added GET form parameter: {param}")
                            
                            # Additionally, extract GET parameters from form action (if any)
                            parsed_action = urlparse(form_data["action"])
                            form_query = parsed_action.query
                            form_params = [p.split('=')[0] for p in form_query.split('&') if p]
                            for p in form_params:
                                if p not in endpoint["GET"]["parameters"]:
                                    endpoint["GET"]["parameters"].append(p)
                                    logging.debug(f"SimpleCrawler: Added GET action parameter: {p}")
                            
                            # Update overall forms list
                            endpoint["all_forms"].append(form_data)

                # Extract and enqueue new links
                links = set()
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith(("javascript:", "mailto:")):
                        continue
                    absolute_href = urljoin(url, href)
                    absolute_href, _ = urldefrag(absolute_href)
                    # Normalize URL
                    absolute_href = self.normalize_url(absolute_href)
                    if self.is_within_domain(absolute_href):
                        links.add(absolute_href)

                with self.lock:
                    for link in links:
                        normalized_link = self.normalize_url(link)
                        if normalized_link not in self.visited:
                            self.visited.add(normalized_link)
                            self.url_queue.put((link, depth + 1))

                # Introduce random delay between requests (1 to 2 seconds)
                delay = random.uniform(1, 2)
                logging.debug(f"SimpleCrawler: Sleeping for {delay:.2f} seconds before next request")
                time.sleep(delay)

            except requests.RequestException as e:
                logging.error(f"SimpleCrawler: Request exception for URL {url}: {e}")
            except Exception as e:
                logging.error(f"SimpleCrawler: Unexpected error for URL {url}: {e}")
            finally:
                self.url_queue.task_done()

    def normalize_url(self, url):
        """
        Normalizes URLs by ensuring consistent formatting while preserving query parameters.
        """
        parsed = urlparse(url)
        scheme = parsed.scheme if parsed.scheme else 'https'  # Prefer https
        netloc = parsed.netloc.lower()
        path = parsed.path or '/'
        query = parsed.query
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        return normalized

    def is_within_domain(self, url):
        """
        Checks if a URL is within the target domain.
        """
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            target = self.target_domain.lstrip('www.')
            current = host.lstrip('www.')
            return current == target or current.endswith(f".{target}")
        except Exception as e:
            logging.warning(f"SimpleCrawler: Invalid URL {url}: {e}")
            return False

    def save_results(self, filename='combined_sitemap.json'):
        """
        Saves the crawler results to a JSON file.
        """
        try:
            logging.info(f"SimpleCrawler: Saving results to {filename}")
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            logging.info("SimpleCrawler: Results successfully saved.")
        except Exception as e:
            logging.error(f"SimpleCrawler: Error saving results to JSON: {e}")


# ------------------------ SeleniumCrawler ------------------------ #


class SeleniumCrawler:
    """
    A Selenium-based web crawler that handles dynamic content to extract endpoints, parameters, forms, and resources.
    """

    def __init__(self, target_url, max_depth=10, delay=1, max_urls_per_depth=10):
        self.target_url = target_url
        self.max_depth = max_depth
        self.delay = delay  # seconds between page requests
        self.results = {"domains": {}}
        self.visited = set()
        self.lock = threading.Lock()
        self.urls_at_depth = {}
        self.max_urls_per_depth = max_urls_per_depth  # Limit the number of URLs crawled per depth

        # Initialize Selenium WebDriver with headless Chrome
        self.driver = self.initialize_webdriver()

    def initialize_webdriver(self):
        """
        Initializes a headless Selenium WebDriver with specified options.
        """
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("user-agent=AttackSurfaceCrawler/1.0")  # Fixed User-Agent
        # Suppress unnecessary logs
        chrome_options.add_argument("--log-level=3")
        try:
            service = ChromeService(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            driver.set_page_load_timeout(30)  # Set a default page load timeout
            return driver
        except WebDriverException as e:
            logging.error(f"SeleniumCrawler: Error initializing WebDriver: {e}")
            sys.exit(1)

    def crawl(self):
        """
        Starts the crawling process from the target URL.
        """
        start_url = self.normalize_url(self.target_url)
        logging.info(f"SeleniumCrawler: Starting crawl at {start_url}")
        self._crawl_url(start_url, 0)
        self.save_results()
        self.driver.quit()

    def _crawl_url(self, url, depth):
        """
        Recursively crawls a given URL up to the specified depth using Selenium.
        """
        if depth > self.max_depth:
            logging.debug(f"SeleniumCrawler: Max depth {self.max_depth} reached at {url}")
            return

        # Check if we've reached the maximum URLs for this depth
        with self.lock:
            if depth not in self.urls_at_depth:
                self.urls_at_depth[depth] = 0
            if self.urls_at_depth[depth] >= self.max_urls_per_depth:
                logging.debug(f"SeleniumCrawler: Max URLs ({self.max_urls_per_depth}) reached for depth {depth}")
                return
            self.urls_at_depth[depth] += 1

        normalized_url = self.normalize_url(url)
        if normalized_url in self.visited:
            logging.debug(f"SimpleCrawler: Already visited {normalized_url}")
            return

        with self.lock:
            self.visited.add(normalized_url)

        logging.info(f"SeleniumCrawler: Crawling URL: {url} at depth {depth}")

        try:
            self.driver.get(url)
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            time.sleep(self.delay)  # Additional delay to allow dynamic content to load

            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path or "/"

            with self.lock:
                if domain not in self.results["domains"]:
                    self.results["domains"][domain] = {"endpoints": {}, "resources": {}}
                if path not in self.results["domains"][domain]["endpoints"]:
                    self.results["domains"][domain]["endpoints"][path] = {
                        "GET": {"available": False, "parameters": []},
                        "POST": {"available": False, "parameters": [], "forms": []},
                        "all_forms": []
                    }

            # Extract forms
            self.extract_forms(url, domain, path)

            # Extract URL parameters
            self.extract_url_parameters(url, domain, path)

            # Extract resources
            self.extract_resources(url, domain)

            # Extract and queue links
            links = self.get_all_links(url)
            for link in links:
                normalized_link = self.normalize_url(link)
                if self.is_within_domain(normalized_link):
                    self._crawl_url(normalized_link, depth + 1)

        except TimeoutException:
            logging.warning(f"SeleniumCrawler: Timeout while loading {url}")
        except WebDriverException as e:
            logging.error(f"SeleniumCrawler: WebDriverException while crawling {url}: {e}")
        except Exception as e:
            logging.error(f"SeleniumCrawler: Unexpected error crawling {url}: {e}")

    def normalize_url(self, url):
        """
        Normalizes URLs by ensuring consistent formatting while preserving query parameters.
        """
        parsed = urlparse(url)
        scheme = parsed.scheme or 'http'
        netloc = parsed.netloc.lower()
        path = parsed.path or '/'
        query = parsed.query
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        return normalized

    def is_within_domain(self, url):
        """
        Checks if a URL is within the target domain.
        """
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            target = urlparse(self.target_url).netloc.lower().lstrip('www.')
            current = host.lstrip('www.')
            return current == target or current.endswith(f".{target}")
        except Exception as e:
            logging.warning(f"SeleniumCrawler: Invalid URL {url}: {e}")
            return False

    def extract_forms(self, current_url, domain, path):
        """
        Extracts all forms from the current page and updates the sitemap.
        """
        try:
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                action = form.get_attribute("action") or current_url
                method = form.get_attribute("method") or "GET"
                method = method.upper()
                inputs = []
                input_elements = form.find_elements(By.TAG_NAME, "input") + \
                                 form.find_elements(By.TAG_NAME, "textarea") + \
                                 form.find_elements(By.TAG_NAME, "select")
                for input_elem in input_elements:
                    input_type = input_elem.get_attribute("type") or input_elem.tag_name
                    name = input_elem.get_attribute("name") or ""
                    input_required = input_elem.get_attribute("required") is not None
                    inputs.append({
                        "name": name,
                        "type": input_type,
                        "required": input_required
                    })
                form_data = {
                    "action": urljoin(current_url, action),
                    "method": method,
                    "inputs": inputs
                }

                parsed_action = urlparse(form_data["action"])
                form_path = parsed_action.path or "/"

                with self.lock:
                    if form_path not in self.results["domains"][domain]["endpoints"]:
                        self.results["domains"][domain]["endpoints"][form_path] = {
                            "GET": {"available": False, "parameters": []},
                            "POST": {"available": False, "parameters": [], "forms": []},
                            "all_forms": []
                        }
                    endpoint = self.results["domains"][domain]["endpoints"][form_path]
                    if method == "POST":
                        endpoint["POST"]["available"] = True
                        if form_data not in endpoint["POST"]["forms"]:
                            endpoint["POST"]["forms"].append(form_data)
                    elif method == "GET":
                        endpoint["GET"]["available"] = True
                        # Extract GET parameters from form inputs
                        form_inputs = [
                            input_elem.get_attribute('name') 
                            for input_elem in form.find_elements(By.TAG_NAME, "input") + 
                                            form.find_elements(By.TAG_NAME, "textarea") + 
                                            form.find_elements(By.TAG_NAME, "select")
                            if input_elem.get_attribute('name')
                        ]
                        
                        for param in form_inputs:
                            if param not in endpoint["GET"]["parameters"]:
                                endpoint["GET"]["parameters"].append(param)
                                logging.debug(f"SeleniumCrawler: Added GET form parameter: {param}")
                        
                        # Additionally, extract GET parameters from form action (if any)
                        parsed_action = urlparse(form_data["action"])
                        form_query = parsed_action.query
                        form_params = [p.split('=')[0] for p in form_query.split('&') if p]
                        for p in form_params:
                            if p not in endpoint["GET"]["parameters"]:
                                endpoint["GET"]["parameters"].append(p)
                                logging.debug(f"SeleniumCrawler: Added GET action parameter: {p}")
                                # Update overall forms list
                                endpoint["all_forms"].append(form_data)
        except TimeoutException:
            logging.warning(f"SeleniumCrawler: Timeout while extracting forms from {current_url}")
        except Exception as e:
            logging.error(f"SeleniumCrawler: Error extracting forms from {current_url}: {e}")

    def extract_url_parameters(self, current_url, domain, path):
        """
        Extracts GET parameters from the current page's URL and updates the sitemap.
        """
        try:
            parsed_url = urlparse(current_url)
            query = parsed_url.query
            if query:
                params = [param.split('=')[0] for param in query.split('&') if param]
                with self.lock:
                    endpoint = self.results["domains"][domain]["endpoints"][path]
                    if not endpoint["GET"]["available"]:
                        endpoint["GET"]["available"] = True
                    for param in params:
                        if param not in endpoint["GET"]["parameters"]:
                            endpoint["GET"]["parameters"].append(param)
        except Exception as e:
            logging.error(f"SeleniumCrawler: Error extracting URL parameters from {current_url}: {e}")

    def extract_resources(self, current_url, domain):
        """
        Extracts resource URLs like scripts, stylesheets, images, iframes, media, etc., and updates the sitemap.
        """
        try:
            resources = {
                "scripts": set(),
                "stylesheets": set(),
                "images": set(),
                "iframes": set(),
                "media": set(),
                "others": set(),
            }

            # Scripts
            script_elements = self.driver.find_elements(By.TAG_NAME, "script")
            for script in script_elements:
                src = script.get_attribute("src")
                if src:
                    absolute_src = urljoin(current_url, src)
                    resources["scripts"].add(absolute_src)

            # Stylesheets
            link_elements = self.driver.find_elements(By.XPATH, "//link[@rel='stylesheet']")
            for link in link_elements:
                href = link.get_attribute("href")
                if href:
                    absolute_href = urljoin(current_url, href)
                    resources["stylesheets"].add(absolute_href)

            # Images
            img_elements = self.driver.find_elements(By.TAG_NAME, "img")
            for img in img_elements:
                src = img.get_attribute("src")
                if src:
                    absolute_src = urljoin(current_url, src)
                    resources["images"].add(absolute_src)

            # Iframes
            iframe_elements = self.driver.find_elements(By.TAG_NAME, "iframe")
            for iframe in iframe_elements:
                src = iframe.get_attribute("src")
                if src:
                    absolute_src = urljoin(current_url, src)
                    resources["iframes"].add(absolute_src)

            # Media (audio, video)
            media_tags = ["audio", "video"]
            for tag in media_tags:
                media_elements = self.driver.find_elements(By.TAG_NAME, tag)
                for media in media_elements:
                    src = media.get_attribute("src")
                    if src:
                        absolute_src = urljoin(current_url, src)
                        resources["media"].add(absolute_src)

            # Others (object, embed, etc.)
            other_tags = ["object", "embed"]
            for tag in other_tags:
                other_elements = self.driver.find_elements(By.TAG_NAME, tag)
                for elem in other_elements:
                    src = elem.get_attribute("data") or elem.get_attribute("src")
                    if src:
                        absolute_src = urljoin(current_url, src)
                        resources["others"].add(absolute_src)

            with self.lock:
                domain_resources = self.results["domains"][domain].get("resources", {})
                for res_type, res_set in resources.items():
                    if res_type not in domain_resources:
                        domain_resources[res_type] = set()
                    domain_resources[res_type].update(res_set)
                self.results["domains"][domain]["resources"] = domain_resources

        except Exception as e:
            logging.error(f"SeleniumCrawler: Error extracting resources from {current_url}: {e}")

    def get_all_links(self, current_url):
        """
        Extracts all unique, absolute links from the current page.
        """
        links = set()
        try:
            elements = self.driver.find_elements(By.TAG_NAME, "a")
            for elem in elements:
                href = elem.get_attribute("href")
                if href and not href.startswith(("javascript:", "mailto:")):
                    absolute_href = urljoin(current_url, href)
                    absolute_href, _ = urldefrag(absolute_href)
                    absolute_href = self.normalize_url(absolute_href)
                    links.add(absolute_href)

            # Additionally, execute JavaScript to find links embedded in scripts or dynamic content
            js_links = self.driver.execute_script("""
                var links = [];
                var elems = document.querySelectorAll("*");
                for (var i=0; i<elems.length; i++) {
                    var elem = elems[i];
                    if (elem.href) {
                        links.push(elem.href);
                    }
                    if (elem.src) {
                        links.push(elem.src);
                    }
                }
                return links;
            """)
            for link in js_links:
                if link and not link.startswith(("javascript:", "mailto:")):
                    absolute_href = urljoin(current_url, link)
                    absolute_href, _ = urldefrag(absolute_href)
                    absolute_href = self.normalize_url(absolute_href)
                    links.add(absolute_href)

        except Exception as e:
            logging.error(f"SeleniumCrawler: Error extracting links from {current_url}: {e}")
        return links

    def save_results(self, filename='combined_sitemap.json'):
        """
        Saves the crawler results to a JSON file.
        """
        try:
            logging.info(f"SeleniumCrawler: Saving results to {filename}")
            # Convert sets to lists for JSON serialization
            for domain, data in self.results["domains"].items():
                for res_type, res_set in data.get("resources", {}).items():
                    data["resources"][res_type] = list(res_set)
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            logging.info("SeleniumCrawler: Results successfully saved.")
        except Exception as e:
            logging.error(f"SeleniumCrawler: Error saving results to JSON: {e}")


# ------------------------- Sitemap Merger ------------------------- #


def merge_sitemaps(simple_sitemap, selenium_sitemap):
    """
    Merges two sitemaps from SimpleCrawler and SeleniumCrawler into a combined sitemap.
    """
    merged = simple_sitemap.copy()

    for domain, data in selenium_sitemap.get('domains', {}).items():
        if domain not in merged['domains']:
            merged['domains'][domain] = {
                "endpoints": {},
                "resources": {}
            }
        elif "resources" not in merged['domains'][domain]:
            merged['domains'][domain]["resources"] = {}

        # Merge resources
            for res_type, resources in data.get('resources', {}).items():
                if res_type not in merged['domains'][domain]["resources"]:
                    merged['domains'][domain]["resources"][res_type] = set(resources)
                else:
                    merged['domains'][domain]["resources"][res_type].update(resources)

        # Merge endpoints
        for endpoint, details in data.get('endpoints', {}).items():
            if endpoint not in merged['domains'][domain]["endpoints"]:
                merged['domains'][domain]["endpoints"][endpoint] = details
            else:
                # Merge GET parameters
                if details.get("GET", {}).get("available"):
                    merged['domains'][domain]["endpoints"][endpoint]["GET"]["available"] = True
                    merged['domains'][domain]["endpoints"][endpoint]["GET"]["parameters"].extend(
                        [p for p in details["GET"].get("parameters", []) if p not in merged['domains'][domain]["endpoints"][endpoint]["GET"]["parameters"]]
                    )
                # Merge POST parameters and forms
                if details.get("POST", {}).get("available"):
                    merged['domains'][domain]["endpoints"][endpoint]["POST"]["available"] = True
                    merged['domains'][domain]["endpoints"][endpoint]["POST"]["parameters"].extend(
                        [p for p in details["POST"].get("parameters", []) if p not in merged['domains'][domain]["endpoints"][endpoint]["POST"]["parameters"]]
                    )
                    for form in details["POST"].get("forms", []):
                        if form not in merged['domains'][domain]["endpoints"][endpoint]["POST"]["forms"]:
                            merged['domains'][domain]["endpoints"][endpoint]["POST"]["forms"].append(form)
                # Merge all_forms
                if "all_forms" in details:
                    if "all_forms" not in merged['domains'][domain]["endpoints"][endpoint]:
                        merged['domains'][domain]["endpoints"][endpoint]["all_forms"] = []
                    for form in details["all_forms"]:
                        if form not in merged['domains'][domain]["endpoints"][endpoint]["all_forms"]:
                            merged['domains'][domain]["endpoints"][endpoint]["all_forms"].append(form)

    # Convert all resource sets to lists for JSON serialization
    for domain, data in merged["domains"].items():
        for res_type, res_set in data.get("resources", {}).items():
            data["resources"][res_type] = list(res_set)

    return merged


# ---------------------------- Main Function ---------------------------- #


def main():
    """
    Main function to execute both crawlers and merge their findings.
    """
    parser = argparse.ArgumentParser(description="Combined Web Crawler for Attack Surface Mapping")
    parser.add_argument('domain', help='Target domain to crawl (e.g., https://example.com)')
    parser.add_argument('--max-depth', type=int, default=7, help='Maximum crawling depth (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='SimpleCrawler timeout in minutes (default: 5)')
    parser.add_argument('--delay', type=int, default=1, help='Delay between Selenium crawler requests in seconds (default: 1)')
    parser.add_argument('--output', type=str, default='parsed_sitemap.json', help='Output JSON file (default: combined_sitemap.json)')
    args = parser.parse_args()

    target_url = args.domain
    max_depth = args.max_depth
    timeout_minutes = args.timeout
    delay = args.delay
    output_file = args.output

    # Validate target_url
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        logging.error("Invalid URL format. Please provide a valid URL (e.g., https://example.com)")
        sys.exit(1)

    target_domain = parsed.netloc.lower()

    # Initialize and run SimpleCrawler
    simple_crawler = SimpleCrawler(target_domain=target_domain, max_depth=max_depth, timeout_minutes=timeout_minutes)
    simple_thread = threading.Thread(target=simple_crawler.crawl)
    simple_thread.start()
    simple_thread.join()

    # Initialize and run SeleniumCrawler
    selenium_crawler = SeleniumCrawler(target_url=target_url, max_depth=max_depth, delay=delay, max_urls_per_depth=10)
    selenium_thread = threading.Thread(target=selenium_crawler.crawl)
    selenium_thread.start()
    selenium_thread.join()

    # Merge sitemaps
    combined_sitemap = merge_sitemaps(simple_crawler.results, selenium_crawler.results)

    # Save combined sitemap to JSON
    try:
        logging.info(f"Saving combined sitemap to {output_file}")
        with open(output_file, 'w') as f:
            json.dump(combined_sitemap, f, indent=4)
        logging.info(f"Combined sitemap successfully saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving combined sitemap to {output_file}: {e}")


if __name__ == "__main__":
    main()