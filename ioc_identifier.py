import os
import sys
import json
import re
import logging
import tempfile
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Set to DEBUG for more verbose output
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

class IOCIdentifier:
    def __init__(self, file_name='response_server_bridge.txt'):
        """
        Initialize the IOC Identifier.

        :param file_name: Name of the server response file located in the CWD.
        """
        self.file_path = os.path.join(os.getcwd(), file_name)
        # logging.info(f"IOC Identifier initialized with file: {self.file_path}")

        self.ioc_patterns = {
            # Credential Patterns - More specific matches
            'aws_access_key': re.compile(r'(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])'),
            'aws_secret_key': re.compile(r'(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9])'),
            'azure_key': re.compile(r'(?<![A-Za-z0-9])sk-[A-Za-z0-9]{32}(?![A-Za-z0-9])'),
            'google_api_key': re.compile(r'(?<![A-Za-z0-9])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9])'),
            'github_token': re.compile(r'(?<![A-Za-z0-9])gh[ps]_[A-Za-z0-9]{36}(?![A-Za-z0-9])'),
            
            # Improved JWT pattern
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+'),
            
            # PII with better validation
            'email_address': re.compile(r'\b[\w\.-]+@[\w\.-]+\.\w{2,}\b'),
            'phone_number': re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b(?![-\d])'),
            
            # Improved credit card pattern with validation
            'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'),
            
            # Security-focused patterns
            'sql_injection': re.compile(r"(?i)(UNION.*SELECT|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM|DROP.*TABLE|EXEC.*sp_|DECLARE.*@|SELECT.*FROM)"),
            'xss_payload': re.compile(r"(?i)(<script.*?>.*?</script>|javascript:|onerror=|onload=|eval\(.*?\)|document\.cookie)"),
            'command_injection': re.compile(r'(?i)(`.*?`|\$\(.*?\)|;&|;\||;\s*\||\/bin\/(?:ba)?sh)'),
            
            # Path traversal with context
            'path_traversal': re.compile(r'(?:\.\./|\.\.\\){2,}'),
            
            # Information leakage patterns
            'server_version': re.compile(r'(?i)(apache/[\d.]+|nginx/[\d.]+|microsoft-iis/[\d.]+)'),
            'internal_ip': re.compile(r'\b(?:127\.0\.0\.1|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)(?:\d{1,3}\.){2}\d{1,3}\b'),
            
            # Enhanced hash patterns
            'md5_hash': re.compile(r'\b[a-fA-F0-9]{32}\b(?![a-fA-F0-9])'),
            'sha1_hash': re.compile(r'\b[a-fA-F0-9]{40}\b(?![a-fA-F0-9])'),
            'sha256_hash': re.compile(r'\b[a-fA-F0-9]{64}\b(?![a-fA-F0-9])'),
            
            # API and endpoint patterns
            'api_endpoint': re.compile(r'https?://[^\s"\'<>]+/(?:api|v[0-9]+)/[^\s"\'<>]+'),
            'sensitive_endpoint': re.compile(r'(?i)/(?:admin|login|logout|auth|users?|config|setup|install)'),
        }

        # Security headers to look for
        self.security_headers = [
            'x-frame-options',
            'x-xss-protection',
            'x-content-type-options',
            'content-security-policy',
            'strict-transport-security',
            'x-permitted-cross-domain-policies',
            'referrer-policy',
            'permissions-policy',
            'cross-origin-opener-policy',
            'cross-origin-embedder-policy',
            'cross-origin-resource-policy',
            'feature-policy',
            'expect-ct',
            'content-security-policy-report-only'
        ]

    def parse_response(self):
        """
        Parse the server response from the fixed .txt file, identify IoCs,
        and overwrite the file with a JSON summary.
        """
        if not os.path.exists(self.file_path):
            logging.error(f"Server response file not found: {self.file_path}")
            return

        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                response_content = f.read()

            if not response_content.strip():
                logging.warning(f"Server response file is empty: {self.file_path}")
                summary = {"error": "Empty server response"}
                self.write_summary(summary)
                return

            headers, body = self.split_headers_body(response_content)
            header_dict = self.parse_headers(headers)

            # Extract security headers
            extracted_security_headers = {
                k: v for k, v in header_dict.items()
                if k.lower() in self.security_headers
            }

            # Extract and parse cookies
            cookies = self.parse_cookies(header_dict.get('set-cookie', []))

            # Parse body with BeautifulSoup
            soup = BeautifulSoup(body, 'html.parser')

            # Extract forms
            forms = self.extract_forms(soup)

            # Extract links and scripts
            links, scripts = self.extract_links_scripts(soup)

            # Extract other resources
            resources = self.extract_resources(soup)

            # Extract potential endpoints
            potential_endpoints = self.extract_potential_endpoints(links, scripts)

            # Extract IoCs from body
            interesting_patterns = self.extract_iocs(body)

            # Compile summary
            summary = {
                "status_code": header_dict.get(':status', 'Unknown'),
                "headers": header_dict,
                "security_headers": extracted_security_headers,
                "cookies": cookies,
                "body_insights": {
                    "forms": forms,
                    "links": links,
                    "scripts": scripts,
                    "resources": resources,
                    "potential_endpoints": list(potential_endpoints),
                    "interesting_patterns": interesting_patterns
                }
            }

            # Overwrite the original file with the summary
            self.write_summary(summary)
            # logging.info(f"IoC analysis completed and summary written to {self.file_path}.")

        except Exception as e:
            logging.error(f"An error occurred while parsing the response: {str(e)}")
            summary = {"error": str(e)}
            self.write_summary(summary)

    def split_headers_body(self, response_text):
        """
        Split HTTP response into headers and body.

        :param response_text: Complete HTTP response as a string.
        :return: Tuple of (headers, body).
        """
        try:
            # HTTP headers are separated from the body by two CRLFs
            header_part, sep, body = response_text.partition('\r\n\r\n')
            if not sep:
                # Fallback to two LF if CRLF not found
                header_part, sep, body = response_text.partition('\n\n')
            return header_part, body
        except Exception as e:
            logging.error(f"Error splitting headers and body: {str(e)}")
            return "", response_text

    def parse_headers(self, headers_text):
        """
        Parse raw headers into a dictionary.

        :param headers_text: Raw headers as a string.
        :return: Dictionary of headers.
        """
        header_dict = {}
        try:
            lines = headers_text.splitlines()
            for line in lines:
                if ': ' in line:
                    name, value = line.split(': ', 1)
                    name_lower = name.lower()
                    if name_lower in header_dict:
                        # Handle multiple headers with the same name
                        if isinstance(header_dict[name_lower], list):
                            header_dict[name_lower].append(value)
                        else:
                            header_dict[name_lower] = [header_dict[name_lower], value]
                    else:
                        header_dict[name_lower] = value
                elif line.startswith('HTTP/'):
                    # Status line, e.g., HTTP/1.1 200 OK
                    parts = line.split(' ')
                    if len(parts) >= 2:
                        header_dict[':status'] = parts[1]
            return header_dict
        except Exception as e:
            logging.error(f"Error parsing headers: {str(e)}")
            return header_dict

    def parse_cookies(self, set_cookie_headers):
        """
        Parse Set-Cookie headers into a list of cookie dictionaries.

        :param set_cookie_headers: Raw Set-Cookie header(s) as a string or list.
        :return: List of cookies with attributes.
        """
        cookies = []
        try:
            if isinstance(set_cookie_headers, list):
                cookie_headers = set_cookie_headers
            else:
                cookie_headers = [set_cookie_headers] if set_cookie_headers else []

            for cookie_str in cookie_headers:
                cookie = {}
                parts = cookie_str.split(';')
                if len(parts) > 0:
                    if '=' in parts[0]:
                        name, value = parts[0].split('=', 1)
                        cookie['name'] = name.strip()
                        cookie['value'] = value.strip()
                for part in parts[1:]:
                    attr = part.strip()
                    if '=' in attr:
                        key, val = attr.split('=', 1)
                        cookie[key.lower()] = val.strip()
                    else:
                        cookie[attr.lower()] = True
                # Security checks
                cookie['secure'] = cookie.get('secure', False)
                cookie['httponly'] = cookie.get('httponly', False)
                if not cookie['secure']:
                    cookie['insecure'] = True
                if not cookie['httponly']:
                    cookie['httponly'] = False
                cookies.append(cookie)
        except Exception as e:
            logging.error(f"Error parsing cookies: {str(e)}")
        return cookies

    def extract_forms(self, soup):
        """
        Extract forms and their input fields from the HTML.

        :param soup: BeautifulSoup object of the HTML body.
        :return: List of forms with details.
        """
        forms = []
        try:
            for form in soup.find_all('form'):
                form_details = {}
                action = form.get('action') if form.get('action') else ''
                form_details['action'] = urljoin(self.get_base_url(), action)
                method = form.get('method', 'GET').upper()
                form_details['method'] = method
                inputs = []
                for input_elem in form.find_all(['input', 'textarea', 'select']):
                    input_details = {
                        'name': input_elem.get('name'),
                        'type': input_elem.get('type', input_elem.name),
                        'required': input_elem.has_attr('required')
                    }
                    inputs.append(input_details)
                form_details['inputs'] = inputs
                forms.append(form_details)
        except Exception as e:
            logging.error(f"Error extracting forms: {str(e)}")
        return forms

    def extract_links_scripts(self, soup):
        """
        Extract all links and script sources from the HTML.

        :param soup: BeautifulSoup object of the HTML body.
        :return: Tuple of lists (links, scripts).
        """
        links = set()
        scripts = set()
        try:
            # Extract all anchor links
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if href.startswith(('http://', 'https://', '/')):
                    full_url = urljoin(self.get_base_url(), href)
                    links.add(full_url)

            # Extract all script sources
            for script_tag in soup.find_all('script', src=True):
                src = script_tag['src']
                if src.startswith(('http://', 'https://', '/')):
                    full_url = urljoin(self.get_base_url(), src)
                    scripts.add(full_url)
        except Exception as e:
            logging.error(f"Error extracting links/scripts: {str(e)}")
        return sorted(links), sorted(scripts)

    def extract_resources(self, soup):
        """
        Extract various resources like stylesheets, images, iframes, media, and others.

        :param soup: BeautifulSoup object of the HTML body.
        :return: Dictionary of resources with lists of URLs.
        """
        resources = {
            'stylesheets': [],
            'images': [],
            'iframes': [],
            'media': [],
            'others': []
        }
        try:
            # Stylesheets
            for link_tag in soup.find_all('link', rel='stylesheet', href=True):
                href = link_tag['href']
                if href.startswith(('http://', 'https://', '/')):
                    full_url = urljoin(self.get_base_url(), href)
                    resources['stylesheets'].append(full_url)

            # Images
            for img_tag in soup.find_all('img', src=True):
                src = img_tag['src']
                if src.startswith(('http://', 'https://', '/')):
                    full_url = urljoin(self.get_base_url(), src)
                    resources['images'].append(full_url)

            # Iframes
            for iframe_tag in soup.find_all('iframe', src=True):
                src = iframe_tag['src']
                if src.startswith(('http://', 'https://', '/')):
                    full_url = urljoin(self.get_base_url(), src)
                    resources['iframes'].append(full_url)

            # Media (audio, video)
            for media_tag in soup.find_all(['audio', 'video'], src=True):
                src = media_tag['src']
                if src.startswith(('http://', 'https://', '/')):
                    full_url = urljoin(self.get_base_url(), src)
                    resources['media'].append(full_url)

            # Others (object, embed, etc.)
            for tag in soup.find_all(['object', 'embed'], src=True):
                src = tag['src']
                if src.startswith(('http://', 'https://', '/')):
                    full_url = urljoin(self.get_base_url(), src)
                    resources['others'].append(full_url)
        except Exception as e:
            logging.error(f"Error extracting resources: {str(e)}")
        return resources

    def extract_potential_endpoints(self, links, scripts):
        """
        Identify potential backend endpoints by analyzing paths in links and scripts.

        :param links: List of extracted links.
        :param scripts: List of extracted script sources.
        :return: Set of potential endpoint paths.
        """
        potential_endpoints = set()
        try:
            for url in links + scripts:
                parsed = urlparse(url)
                path = parsed.path
                if path and path != '/':
                    potential_endpoints.add(path)
        except Exception as e:
            logging.error(f"Error extracting potential endpoints: {str(e)}")
        return potential_endpoints

    def extract_iocs(self, body):
        """
        Detect IoCs within the response body using regex patterns.

        :param body: The response body as a string.
        :return: List of detected IoCs with type and value.
        """
        matches = []
        try:
            for ioc_type, pattern in self.ioc_patterns.items():
                for match in pattern.finditer(body):
                    # Avoid duplicates
                    if not any(m['type'] == ioc_type and m['value'] == match.group(0) for m in matches):
                        matches.append({
                            'type': ioc_type,
                            'value': match.group(0)
                        })
        except Exception as e:
            logging.error(f"Error extracting IoCs: {str(e)}")
        return matches

    def get_base_url(self):
        """
        Retrieve the base URL from the server response headers or default to 'http://localhost'.

        :return: Base URL as a string.
        """
        # Since parsing the base URL isn't required, return a default or placeholder
        # This can be enhanced to extract from headers if needed
        return 'http://localhost'

    def write_summary(self, summary):
        """
        Overwrite the original .txt file with the JSON summary atomically.

        :param summary: Dictionary containing the analysis summary.
        """
        try:
            dir_name = os.path.dirname(self.file_path) or '.'
            with tempfile.NamedTemporaryFile('w', delete=False, dir=dir_name, encoding='utf-8') as tmp_file:
                json.dump(summary, tmp_file, indent=4, ensure_ascii=False)
                temp_name = tmp_file.name
            os.replace(temp_name, self.file_path)  # Atomic operation
        except Exception as e:
            logging.error(f"Error writing summary to file: {str(e)}")

def main():
    """
    Main function to execute the IOC Identifier.
    """
    # Initialize the IOC Identifier
    identifier = IOCIdentifier()

    # Parse the response and identify IoCs
    identifier.parse_response()

if __name__ == "__main__":
    main()