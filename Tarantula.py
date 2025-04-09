import io
import threading
import traceback
import re
import logging
import sys
import simplejson
import urllib3
from urllib.parse import parse_qs, urlparse, quote_plus
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor
import random
import os
import time
from html.parser import HTMLParser
from tkinter import simpledialog, ttk, messagebox
import tkinter as tk
import subprocess

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    from urllib import quote  # Python 2
except ImportError:
    from urllib.parse import quote  # Python 3

class CallableTask:
    def __init__(self, func):
        self.func = func
    
    def __call__(self):
        try:
            self.func()
            return True  # Indicate success
        except Exception as e:
            logging.error("Exception in CallableTask: %s", str(e))
            logging.error(traceback.format_exc())
            return False  # Indicate failure
        
import random
import os
import time
import logging
import time
from concurrent.futures import ThreadPoolExecutor
import traceback
import threading
import traceback
import logging
import sys
import simplejson
import subprocess  # To run external scripts
import os
import time
try:
    from html.parser import HTMLParser
except ImportError:
    from HTMLParser import HTMLParser


# Define a FormParser using HTMLParser for accurate form extraction
class FormParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.forms = []
        self.in_form = False
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == 'form':
            self.in_form = True
            self.current_form = {
                'action': '',
                'method': 'GET',
                'inputs': []
            }
            for attr in attrs:
                attr_name = attr[0].lower()
                attr_value = attr[1]
                if attr_name == 'action':
                    self.current_form['action'] = attr_value
                elif attr_name == 'method':
                    self.current_form['method'] = attr_value.upper()
        elif self.in_form and tag == 'input':
            input_field = {
                'name': '',
                'type': 'text',
                'required': False
            }
            for attr in attrs:
                attr_name = attr[0].lower()
                attr_value = attr[1]
                if attr_name == 'name':
                    input_field['name'] = attr_value
                elif attr_name == 'type':
                    input_field['type'] = attr_value.lower()
                elif attr_name == 'required':
                    input_field['required'] = True
            if self.current_form is not None:
                self.current_form['inputs'].append(input_field)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == 'form' and self.in_form:
            self.in_form = False
            if self.current_form is not None:
                self.forms.append(self.current_form)
                self.current_form = None

    def get_forms(self):
        return self.forms


class PayloadTracker:
    def __init__(self):
        self.failed_payloads = {
            "endpoints": {},      # Track by endpoint URL
            "parameters": {},     # Track by parameter name
            "forms": {},         # Track by form signature
            "combinations": {}    # Track endpoint+parameter/form combinations
        }
        
        # Load existing history if available
        self.load_history()
        
    def track_failure(self, context, payload, response):
        try:
            """Track failed payload with full context"""
            logging.debug("=== Tracking New Failure ===")
            logging.debug("Storage Context: %s" % context)
            
            timestamp = time.time()
            parsed_url = urlparse(context['url'])
            base_url = "%s://%s%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path)
            endpoint_id = "%s:%s" % (context['method'], base_url)
            param_id = context.get('parameter')
            form_id = self.generate_form_id(context.get('form')) if context.get('form') else None
            combo_id = "%s:%s" % (endpoint_id, param_id or form_id)

            logging.debug("Storage Endpoint ID: %s" % endpoint_id)
            logging.debug("Storage Parameter ID: %s" % param_id)

            logging.debug("Generated IDs:")
            logging.debug("Endpoint ID: %s" % endpoint_id)
            logging.debug("Parameter ID: %s" % param_id) 
            logging.debug("Form ID: %s" % form_id)
            logging.debug("Combo ID: %s" % combo_id)

            # Handle response object or string
            if hasattr(response, 'getStatusCode'):
                response_code = response.getStatusCode()
                response_length = len(response.getResponse())
            else:
                response_code = 0  # Default value when status code is not available
                response_length = len(str(response))

            failure_data = {
                "payload": payload,
                "timestamp": timestamp,
                "response_code": response_code,
                "response_length": response_length,
                "technique_type": self.classify_technique(payload),
                "pattern_signature": self.generate_pattern_signature(payload),
                "context": {
                    "endpoint": context['url'],
                    "method": context['method'],
                    "parameter": param_id,
                    "form": context.get('form')
                }
            }

            logging.debug("Created failure data: %s" % failure_data)

            # Update all tracking levels
            self._update_tracking("endpoints", endpoint_id, failure_data)
            if param_id:
                self._update_tracking("parameters", param_id, failure_data)
            if form_id:
                self._update_tracking("forms", form_id, failure_data)
            self._update_tracking("combinations", combo_id, failure_data)

            logging.debug("Current failed_payloads state:")
            logging.debug("Endpoints: %s" % self.failed_payloads['endpoints'].keys())
            logging.debug("Parameters: %s" % self.failed_payloads['parameters'].keys()) 
            logging.debug("Forms: %s" % self.failed_payloads['forms'].keys())
            logging.debug("Combinations: %s" % self.failed_payloads['combinations'].keys())

            # Save after updating
            self.save_history()
            logging.debug("Saving history to disk...")
            self.save_history()
            logging.debug("History saved")

        except Exception as e:
            logging.error("Error tracking failed payload: %s" % str(e))
            logging.error(traceback.format_exc())

    def generate_pattern_signature(self, payload):
        """Generate a signature for payload pattern matching"""
        if not payload:
            return "empty_payload"
            
        try:
            signature = {
                "length": len(payload),
                "character_classes": self.identify_character_classes(payload),
                "structure": self.analyze_payload_structure(payload),
                "special_chars": list(set(re.findall(r'[^a-zA-Z0-9\s]', payload))),
                "repeated_patterns": self.find_repeated_sequences(payload)
            }
            return signature
            
        except Exception as e:
            logging.error("Error generating pattern signature: %s" % str(e))
            return "signature_error"
        
    def _update_patterns(self, tracking, failure_data):
        """Update pattern analysis for a tracking category"""
        try:
            # Initialize patterns if not present or incomplete
            if "patterns" not in tracking:
                tracking["patterns"] = {}
                
            patterns = tracking["patterns"]
            
            # Initialize all pattern categories if they don't exist
            if "techniques" not in patterns:
                patterns["techniques"] = {}
            if "character_classes" not in patterns:
                patterns["character_classes"] = {}
            if "payload_lengths" not in patterns:
                patterns["payload_lengths"] = []
            if "common_structures" not in patterns:
                patterns["common_structures"] = {}
            if "response_codes" not in patterns:
                patterns["response_codes"] = {}
            if "special_chars" not in patterns:
                patterns["special_chars"] = set()
            if "repeated_sequences" not in patterns:
                patterns["repeated_sequences"] = set()

            # Update technique frequency
            technique = failure_data.get("technique_type", "unknown")
            patterns["techniques"][technique] = patterns["techniques"].get(technique, 0) + 1

            # Get pattern signature
            signature = failure_data.get("pattern_signature", {})
            
            # Update character classes
            for char_class in signature.get("character_classes", []):
                patterns["character_classes"][char_class] = patterns["character_classes"].get(char_class, 0) + 1

            # Update payload lengths
            patterns["payload_lengths"].append(signature.get("length", 0))
            if len(patterns["payload_lengths"]) > 100:  # Keep last 100 lengths
                patterns["payload_lengths"] = patterns["payload_lengths"][-100:]

            # Update structure patterns
            structure = signature.get("structure", {})
            for key, value in structure.items():
                if key not in patterns["common_structures"]:
                    patterns["common_structures"][key] = {}
                str_value = str(value)  # Convert to string for consistent dictionary keys
                patterns["common_structures"][key][str_value] = patterns["common_structures"][key].get(str_value, 0) + 1

            # Update response code frequency
            response_code = failure_data.get("response_code", "unknown")
            patterns["response_codes"][response_code] = patterns["response_codes"].get(response_code, 0) + 1

            # Update special characters
            patterns["special_chars"] = list(set(list(patterns.get("special_chars", [])) + signature.get("special_chars", [])))[:100]
    
            # Update repeated sequences
            patterns["repeated_sequences"] = list(set(list(patterns.get("repeated_sequences", [])) + signature.get("repeated_patterns", [])))[:100]

            # Update timestamp
            tracking["last_updated"] = time.time()

        except Exception as e:
            logging.error("Error updating patterns: %s" % str(e))
            logging.error("Current tracking state: %s" % tracking)
            logging.error("Current patterns state: %s" % tracking.get('patterns', {}))
            logging.error(traceback.format_exc())


    def identify_character_classes(self, payload):
        """Identify character classes used in payload"""
        classes = set()
        if re.search(r'[a-z]', payload): classes.add('lowercase')
        if re.search(r'[A-Z]', payload): classes.add('uppercase')
        if re.search(r'[0-9]', payload): classes.add('numeric')
        if re.search(r'[^a-zA-Z0-9\s]', payload): classes.add('special')
        return list(classes)

    def _update_tracking(self, category, identifier, failure_data):
        """Update tracking for a specific category"""
        if identifier not in self.failed_payloads[category]:
            self.failed_payloads[category][identifier] = {
                "failures": [],
                "patterns": {},
                "technique_stats": {},
                "last_updated": time.time()
            }
            
        tracking = self.failed_payloads[category][identifier]
        tracking["failures"].append(failure_data)
        
        # Update pattern analysis
        self._update_patterns(tracking, failure_data)
        
        # Limit history size while keeping pattern analysis
        if len(tracking["failures"]) > 100:  # Keep last 100 failures
            tracking["failures"] = tracking["failures"][-100:]

    def get_context_failures(self, context):
        """Get all relevant failures for a context"""
        endpoint_id = "%s:%s" % (context['method'], context['url'])
        param_id = context.get('parameter')
        form_id = self.generate_form_id(context.get('form')) if context.get('form') else None
        combo_id = "%s:%s" % (endpoint_id, param_id or form_id)


        relevant_failures = {
            "endpoint_failures": self.failed_payloads["endpoints"].get(endpoint_id, {}).get("failures", []),
            "parameter_failures": self.failed_payloads["parameters"].get(param_id, {}).get("failures", []) if param_id else [],
            "form_failures": self.failed_payloads["forms"].get(form_id, {}).get("failures", []) if form_id else [],
            "combination_failures": self.failed_payloads["combinations"].get(combo_id, {}).get("failures", []),
            "patterns": self.analyze_combined_patterns(endpoint_id, param_id, form_id, combo_id)
        }
        
        return relevant_failures

    def generate_form_id(self, form_data):
        """Generate unique identifier for a form"""
        if not form_data:
            return None
            
        form_elements = [
            form_data.get('action', ''),
            form_data.get('method', ''),
            sorted([field.get('name', '') for field in form_data.get('inputs', [])])
        ]
        
        md = MessageDigest.getInstance("MD5")
        md.update(String(str(form_elements)).getBytes("UTF-8"))
        return "".join([format(b & 0xff, '02x') for b in md.digest()])
    
    def analyze_payload_structure(self, payload):
        """Analyze the structure of the payload"""
        structure = {
            "starts_with": payload[:10],  # First 10 chars
            "ends_with": payload[-10:],   # Last 10 chars
            "contains_sql": bool(re.search(r'(union|select|from|where|and|or|order by)', payload.lower())),
            "contains_script": bool(re.search(r'(<script|javascript:|onerror=|onload=)', payload.lower())),
            "contains_path": bool(re.search(r'(\.\.\/|\.\.\\|\/etc\/|c:\\)', payload.lower())),
            "contains_protocol": bool(re.search(r'(http:|https:|file:|ftp:)', payload.lower()))
        }
        return structure


    def find_repeated_sequences(self, payload):
        """Find repeated sequences in payload"""
        sequences = []
        # Look for sequences of 2-10 characters that repeat
        for length in range(2, min(11, len(payload))):
            for i in range(len(payload) - length + 1):
                sequence = payload[i:i+length]
                if payload.count(sequence) > 1:
                    sequences.append(sequence)
        return list(set(sequences))[:5]  # Return up to 5 unique repeated sequences

    def classify_technique(self, payload):
        """Basic classification of payload technique"""
        if not payload:
            return "unknown"

        if isinstance(payload, bytes):
            payload = payload.lower()
        
        # SQL Injection patterns
        if any(x in payload for x in ["'", "\"", "union", "select", "from", "where", 
            "or 1=1", "or true", "' --", "/*", "*/", "@@version", "benchmark",
            "sleep(", "waitfor", "delay '", "pg_sleep", "order by"]):
            return "sql_injection"
            
        # XSS patterns    
        elif any(x in payload for x in ["<", ">", "script", "onerror", "onload", "alert(", 
            "img src", "svg/onload", "javascript:", "vbscript:", "data:", "onmouseover",
            "onfocus", "onblur", "onclick", "ondblclick", "onkeyup", "onkeydown"]):
            return "xss"
            
        # Path Traversal patterns
        elif any(x in payload for x in ["../", "..\\", "etc/passwd", "windows/win.ini",
            ".htaccess", "web.config", "boot.ini", "/proc/self/", "%2e%2e%2f",
            "..;/", "file:///"]):
            return "path_traversal"
            
        # SSRF patterns    
        elif any(x in payload for x in ["http://", "https://", "file://", "dict://", "ftp://",
            "gopher://", "ldap://", "tftp://", "dns:", "netdoc:", "jar:", "127.0.0.1",
            "localhost"]):
            return "ssrf"
            
        # Command Injection patterns
        elif any(x in payload for x in ["&", "|", ";", "`", "$", "$(", ")", "{", "}", "eval",
            "system(", "exec(", "shell_exec", "passthru", "popen", "proc_open"]):
            return "command_injection"
            
        # XXE patterns
        elif any(x in payload for x in ["<!entity", "<!DOCTYPE", "xml", "SYSTEM", "PUBLIC"]):
            return "xxe"
            
        # Template Injection
        elif any(x in payload for x in ["${", "#{", "<%", "%>", "{{'", "'}}", "[[", "]]"]):
            return "template_injection"
            
        # LDAP Injection
        elif any(x in payload for x in ["*)(", "*)(&", ")(!", ")(|", ")(="]):
            return "ldap_injection"
            
        return "other"
    
    def _format_failures(self, failures):
        """Format failures for AI prompt including confidence scores"""
        try:
            if not failures:
                return "None"
                
            formatted = []
            for failure in failures:
                try:
                    formatted.append(
                        "Payload: %s\n"
                        "Technique: %s\n" 
                        "Response Code: %s\n"
                        "Timestamp: %s\n" % (
                            failure.get('payload', 'unknown'),
                            failure.get('technique_type', 'unknown'),
                            failure.get('response_code', 'unknown'),
                            time.ctime(failure.get('timestamp', time.time()))
                        )
                    )
                except Exception as e:
                    logging.error("Error formatting individual failure: %s" % str(e))
                    continue
                    
            return "\n".join(formatted) if formatted else "None"
            
        except Exception as e:
            logging.error("Error in _format_failures: %s" % str(e))
            return "Error formatting failures"
    
    def format_failed_history(self, failed_history):
        """Format failed payload history for AI prompt"""
        formatted = []
        
        for category, failures in failed_history.items():
            if failures:
                formatted.append("\n%s:" % category)
                for failure in failures:
                    formatted.append(
                        "Payload: %s\n"
                        "Technique: %s\n" 
                        "Response Code: %s\n"
                        "Timestamp: %s\n" % (
                            failure['payload'],
                            failure['technique_type'],
                            failure['response_code'], 
                            time.ctime(failure['timestamp'])
                        ))
    
        return "\n".join(formatted)

    def format_for_ai_prompt(self, analysis_data):
        """Format failed payload history for AI prompt"""
        try:
            logging.debug("Formatting AI prompt with analysis data: %s" % analysis_data)
            
            # Get context from analysis_data
            context = analysis_data.get("context", {})
            
            # Get values safely from analysis_data, not context
            method = analysis_data.get('method', 'GET')
            url = analysis_data.get('endpoint', 'unknown')
            param = analysis_data.get('parameter')
            form = context.get('form')  # form might be in the context
            endpoint_id = "%s:%s" % (method, url)
            param_id = param if param else None
            form_id = self.generate_form_id(form) if form else None
            combo_id = "%s:%s" % (endpoint_id, param_id or form_id)

            logging.debug("Looking up failures with IDs:")
            logging.debug("Endpoint ID: %s" % endpoint_id)
            logging.debug("Parameter ID: %s" % param_id)
            logging.debug("Form ID: %s" % form_id)
            logging.debug("Combo ID: %s" % combo_id)

            logging.debug("=== Available IDs in storage ===")
            logging.debug("Endpoint IDs: %s" % list(self.failed_payloads['endpoints'].keys()))  
            logging.debug("Parameter IDs: %s" % list(self.failed_payloads['parameters'].keys()))
            logging.debug("Form IDs: %s" % list(self.failed_payloads['forms'].keys()))
            logging.debug("Combo IDs: %s" % list(self.failed_payloads['combinations'].keys()))

            failures = {
                "endpoint_failures": self.failed_payloads["endpoints"].get(endpoint_id, {}).get("failures", [])[-5:],
                "parameter_failures": self.failed_payloads["parameters"].get(param_id, {}).get("failures", [])[-5:] if param_id else [],
                "form_failures": self.failed_payloads["forms"].get(form_id, {}).get("failures", [])[-5:] if form_id else [],
                "combination_failures": self.failed_payloads["combinations"].get(combo_id, {}).get("failures", [])[-5:]
                # "patterns": self.analyze_combined_patterns(endpoint_id, param_id, form_id, combo_id)
            }
            
            prompt_data = {
                "endpoint_history": self._format_failures(failures["endpoint_failures"]),
                "parameter_history": self._format_failures(failures["parameter_failures"]),
                "form_history": self._format_failures(failures["form_failures"]),
                "combination_history": self._format_failures(failures["combination_failures"])
                # "observed_patterns": failures["patterns"]
            }
            
            # Convert any sets in observed_patterns to lists
            def convert_sets_to_lists(obj):
                if isinstance(obj, dict):
                    return {key: convert_sets_to_lists(value) for key, value in obj.items()}
                elif isinstance(obj, set):
                    return list(obj)
                elif isinstance(obj, list):
                    return [convert_sets_to_lists(item) for item in obj]
                return obj

            # serializable_patterns = convert_sets_to_lists(prompt_data['observed_patterns'])

            return (
                "Previous failures for this context:\n\n"
                "Endpoint-specific failures:\n%s\n\n"
                "Parameter-specific failures:\n%s\n\n"
                "Form-specific failures:\n%s\n\n" 
                "Combined context failures:\n%s\n\n"
                #"Observed patterns to avoid:\n%s"
            ) % (
                prompt_data['endpoint_history'],
                prompt_data['parameter_history'], 
                prompt_data['form_history'],
                prompt_data['combination_history']
                # simplejson.dumps(serializable_patterns, indent=2)
            )

        except Exception as e:
            logging.error("Error formatting AI prompt: %s" % str(e))
            logging.error("Analysis data received: %s" % analysis_data)
            logging.error(traceback.format_exc())
            return "No previous failure history available"

    def analyze_combined_patterns(self, endpoint_id, param_id, form_id, combo_id):
        """Analyze patterns across all context levels"""
        patterns = {
            "common_techniques": set(),
            "failed_patterns": set(),
            "response_patterns": set(),
            "security_controls": set(),
            "special_chars": set(),
            "repeated_sequences": set(),
            "techniques": {},
            "character_classes": {},
            "payload_lengths": [],
            "common_structures": {},
            "response_codes": {}
        }
        
        # Collect patterns from all relevant contexts
        contexts = [
            self.failed_payloads["endpoints"].get(endpoint_id, {}).get("patterns", {}),
            self.failed_payloads["parameters"].get(param_id, {}).get("patterns", {}),
            self.failed_payloads["forms"].get(form_id, {}).get("patterns", {}),
            self.failed_payloads["combinations"].get(combo_id, {}).get("patterns", {})
        ]
        
        # Merge patterns
        for context_patterns in contexts:
            for category, items in context_patterns.items():
                if isinstance(items, (set, list)):
                    if isinstance(patterns[category], list):
                        patterns[category].extend(items)
                    elif isinstance(patterns[category], set):
                        patterns[category].update(items)
                elif isinstance(items, dict):
                    for k, v in items.items():
                        if k not in patterns:
                            patterns[k] = {}
                        # Convert dictionary to string representation for key
                        v_key = str(v) if isinstance(v, dict) else v
                        patterns[k][v_key] = patterns[k].get(v_key, 0) + 1
                            
        return patterns
    
    def load_history(self):
        """Load failed payload history from disk"""
        try:
            history_file = "failed_payloads.json"
            try:
                if os.path.exists(history_file):
                    f =  open(history_file, 'r')
                    data = simplejson.load(f)
                    
                    # Convert lists back to sets where needed
                    for category, category_data in data.items():
                        for identifier, tracking_data in category_data.items():
                            tracking_data["patterns"]["special_chars"] = set(tracking_data["patterns"]["special_chars"])
                            tracking_data["patterns"]["repeated_sequences"] = set(tracking_data["patterns"]["repeated_sequences"])
                    
                    self.failed_payloads = data
                    logging.debug("Loaded failed payload history")
                    logging.debug("Loaded data: %s" % self.failed_payloads)
                else:
                    logging.debug("No history file found, starting fresh")
                    self.failed_payloads = {
                        "endpoints": {},
                        "parameters": {},
                        "forms": {},
                        "combinations": {}
                    }
                    
            finally:
                f.close()
        except Exception as e:
            logging.error("Error loading failed payload history: %s" % str(e))
            logging.error(traceback.format_exc())
            self.failed_payloads = {
                "endpoints": {},
                "parameters": {},
                "forms": {},
                "combinations": {}
            }

    def save_history(self):
        """Save failed payload history to disk"""
        try:
            history_file = "failed_payloads.json"
            
            # Convert sets to lists for JSON serialization
            serializable_data = {}
            for category, category_data in self.failed_payloads.items():
                serializable_data[category] = {}
                for identifier, tracking_data in category_data.items():
                    serializable_data[category][identifier] = {
                        "failures": tracking_data["failures"],
                        "patterns": {
                            "techniques": tracking_data["patterns"]["techniques"],
                            "character_classes": tracking_data["patterns"]["character_classes"],
                            "payload_lengths": tracking_data["patterns"]["payload_lengths"],
                            "common_structures": tracking_data["patterns"]["common_structures"],
                            "response_codes": tracking_data["patterns"]["response_codes"],
                            "special_chars": list(tracking_data["patterns"]["special_chars"]),
                            "repeated_sequences": list(tracking_data["patterns"]["repeated_sequences"])
                        },
                        "technique_stats": tracking_data["technique_stats"],
                        "last_updated": tracking_data["last_updated"]
                    }
            
            f = open(history_file, 'w')
            simplejson.dump(serializable_data, f, indent=2)
            logging.debug("Saved failed payload history")
            logging.debug("Saved data: %s" % serializable_data)
                
        except Exception as e:
            logging.error("Error saving failed payload history: %s" % str(e))
            logging.error(traceback.format_exc())

        finally:
            f.close()

import requests
import threading

from tkinter import simpledialog
from tkinter import ttk
import tkinter as tk
from tkinter import messagebox

# Selenium imports
from selenium import webdriver  # Added
from selenium.webdriver.chrome.options import Options  # Added
from selenium.webdriver.common.by import By  # Added
from selenium.webdriver.support.ui import WebDriverWait  # Added
from selenium.webdriver.support import expected_conditions as EC  # Added
from selenium.common.exceptions import (  # Added
    NoSuchElementException,
    NoAlertPresentException,
    TimeoutException
)  # Added

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib.parse import quote_plus
from urllib.parse import urlencode
from urllib.parse import unquote

class WebScanner:
    def __init__(self):
        # Initialize variables
        self.target_domain = None
        self.json_file_path = "parsed_sitemap.json"  # Make this consistent
        self.autonomous_mode = False
        self.executor = None
        self.results = {"domains": {}}
        self.api_key = None
        self.parsed_data = None  # Add this to track parsed data
        
        # Load API key from config
        try:
            with open("config.txt", "r") as f:
                for line in f:
                    if line.startswith("OPENAI_API_KEY="):
                        self.api_key = line.strip().split("=")[1]
                        break
        except FileNotFoundError:
            logging.warning("config.txt not found. Please enter API key in GUI.")
        
        # Initialize state variables
        self.iteration = 0
        self.max_iterations = 5
        
        # Initialize counters
        self.counter_lock = threading.Lock()
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.vulnerabilities_found = 0
        self.failed_requests_log = []
        
        # Notification settings
        self.recent_failed_requests = 0
        self.notification_threshold = 10
        self.notification_interval = 300  # 5 minutes
        
        # Initialize thread pool
        self.executor = ThreadPoolExecutor(max_workers=60)
        self.futures = []
        
        # Results tracking
        self.vulnerabilities_to_write = []
        self.payload_tracker = PayloadTracker()
        
        self.tested_endpoints = set()  # Track tested endpoints
        self.endpoint_test_counts = {}  # Track how many times each endpoint has been tested
        
        # Initialize headless browser
        self.browser = self.setup_headless_browser()
        
        # Setup logging
        logging.basicConfig(
            filename="scanner.log",
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)s:%(message)s",
        )
        sys.excepthook = self.log_uncaught_exceptions
        f = open("scanner.log", "w")
        f.close()
        logging.info("Scanner initialized.")
        
        # Initialize GUI
        self.setup_gui()

    def setup_headless_browser(self):
        """Initialize headless Chrome browser"""
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            
            # Add custom headers
            chrome_options.add_argument('--user-agent=Mozilla/5.0')
            chrome_options.add_argument('--accept=*/*')
            chrome_options.add_argument('--hackerone=thevinci')
            
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(30)
            return driver
        except Exception as e:
            logging.error(f"Failed to setup headless browser: {str(e)}")
            return None
        

    def setup_gui(self):
        """Set up the GUI using tkinter instead of Swing"""
        self.root = tk.Tk()
        self.root.title("Web Scanner")

        # API Key frame
        api_frame = tk.LabelFrame(self.root, text="OpenAI API Key")
        api_frame.pack(fill=tk.X, padx=5, pady=5)

        self.api_key_var = tk.StringVar(value=self.api_key if self.api_key else "")
        tk.Label(api_frame, text="API Key:").pack(side=tk.LEFT)
        self.api_key_entry = tk.Entry(api_frame, textvariable=self.api_key_var, width=50, show="*")
        self.api_key_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(api_frame, text="Save", command=self.save_api_key).pack(side=tk.LEFT, padx=5)

        # Controls frame
        controls = tk.Frame(self.root)
        controls.pack(fill=tk.X, padx=5, pady=5)

        # Max iterations
        tk.Label(controls, text="Max Iterations:").pack(side=tk.LEFT)
        self.max_iter_var = tk.StringVar(value="5")
        tk.Entry(controls, textvariable=self.max_iter_var, width=5).pack(side=tk.LEFT)

        # Buttons
        tk.Button(controls, text="1. Parse Sitemap", command=self.parse_sitemap).pack(side=tk.LEFT, padx=5)
        self.start_btn = tk.Button(controls, text="2. Start Testing", command=self.start_autonomous_cycle)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk.Button(controls, text="Stop", command=self.stop_autonomous_mode, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        tk.Button(controls, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        tk.Button(self.root, text="Copy Selected", command=self.copy_selected).pack(pady=5)

        # Status
        self.status_var = tk.StringVar(value="Status: Enter target domain to begin")
        tk.Label(controls, textvariable=self.status_var).pack(side=tk.LEFT, padx=20)

        # Progress frame
        progress = tk.LabelFrame(self.root, text="Scan Progress")
        progress.pack(fill=tk.X, padx=5, pady=5)

        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(progress, variable=self.progress_var)
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)

        # Progress labels
        self.total_var = tk.StringVar(value="Total Requests: 0")
        self.success_var = tk.StringVar(value="Successful Requests: 0") 
        self.failed_var = tk.StringVar(value="Failed Requests: 0")

        tk.Label(progress, textvariable=self.total_var).pack()
        tk.Label(progress, textvariable=self.success_var).pack()
        tk.Label(progress, textvariable=self.failed_var).pack()

        # Output text area
        output_frame = tk.LabelFrame(self.root, text="Scanner Output")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.text_area = tk.Text(output_frame, height=15)
        scroll = tk.Scrollbar(output_frame)
        self.text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.text_area.config(yscrollcommand=scroll.set)
        scroll.config(command=self.text_area.yview)

        # Results table
        table_frame = tk.LabelFrame(self.root, text="Scan Results")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("Method", "Endpoint", "Parameters", "Form Details", "Vulnerability Confidence")
        self.results_table = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        for col in columns:
            self.results_table.heading(col, text=col)
            self.results_table.column(col, width=200)

        table_scroll = tk.Scrollbar(table_frame)
        self.results_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        table_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.results_table.config(yscrollcommand=table_scroll.set)
        table_scroll.config(command=self.results_table.yview)

    def run(self):
        """Start the GUI event loop"""
        self.root.mainloop()


    def copy_selected(self):
        selected_item = self.results_table.selection()
        if not selected_item:
            messagebox.showinfo("Information", "No item selected to copy.")
            return
        
        item_values = self.results_table.item(selected_item)['values']
        clipboard_data = '\t'.join(item_values)  # Use tab as a separator for copying
        self.root.clipboard_clear()  # Clear the clipboard
        self.root.clipboard_append(clipboard_data)  # Copy the data to the clipboard
        messagebox.showinfo("Copied", "Selected entry has been copied to clipboard.")

    def update_button_states(self):
        """Enable or disable buttons based on the parsing status."""
        try:
            sitemap_parsed = self.is_sitemap_parsed()
            # Update Tkinter button states
            if hasattr(self, 'start_btn'):
                self.start_btn.config(state='normal' if sitemap_parsed else 'disabled')
            if hasattr(self, 'stop_btn'):
                self.stop_btn.config(state='normal' if sitemap_parsed else 'disabled')
            
            # Update status label
            if not sitemap_parsed:
                self.status_var.set("Status: Please parse sitemap first")
            else:
                self.status_var.set("Status: Ready for testing")
        except Exception as e:
            logging.error(f"Error updating button states: {str(e)}")
            self.status_var.set("Status: Error updating interface")

    def is_sitemap_parsed(self):
        """Check if the sitemap has been parsed and data is available."""
        try:
            return (os.path.exists(self.json_file_path) and 
                   os.path.getsize(self.json_file_path) > 0 and 
                   self.parsed_data is not None)
        except Exception as e:
            logging.error(f"Error checking sitemap status: {str(e)}")
            return False

    def get_tab_caption(self):
        return "Tarantula"

    def get_ui_component(self):
        return self.panel

    def process_http_message(self, tool_flag, message_is_request, url, headers, body):
        """Process HTTP messages using Python requests instead of Burp"""
        logging.debug(
            f"process_http_message called. Message is request: {message_is_request}"
        )

        # Parse URL to get host
        parsed_url = urlparse(url)
        message_host = parsed_url.netloc

        # Normalize domains for comparison (remove www. if present)
        normalized_message_host = message_host.replace('www.', '')
        normalized_target = self.target_domain.replace('www.', '') if self.target_domain else None

        if self.target_domain is None:
            # Set target domain from first request
            self.target_domain = message_host
            self.update_status()
            self.log_message(f"Target domain set to: {self.target_domain}")
            return

        # Compare normalized domains
        if normalized_message_host != normalized_target:
            return

        # Process the message using requests if needed
        if message_is_request:
            try:
                response = requests.request(
                    method=headers.get('method', 'GET'),
                    url=url,
                    headers=headers,
                    data=body
                )
                return response
            except requests.exceptions.RequestException as e:
                logging.error(f"Request failed: {str(e)}")
                return None

    def trigger_parsing_script(self):
        """Trigger the Selenium parser script and capture its output."""
        try:
            # Path to the Selenium parser script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            parser_script = os.path.join(script_dir, "selenium_parser.py")
            if not os.path.exists(parser_script):
                self.update_text_area("Parser script not found: %s\n" % parser_script)
                logging.error("Parser script not found: %s" % parser_script)
                return
                
            # Command to execute the parser script
            command = "python %s https://%s" % (parser_script, self.target_domain)
            logging.debug("Executing command: %s" % command)
            self.update_text_area("Launching Selenium crawler script...\n")
            
            # Start the subprocess
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )

            # Start threads to read stdout and stderr
            stdout_thread = threading.Thread(target=self.read_stream, args=(process.stdout, False))
            stdout_thread.setDaemon(True)
            stdout_thread.start()
            
            stderr_thread = threading.Thread(target=self.read_stream, args=(process.stderr, True))
            stderr_thread.setDaemon(True)
            stderr_thread.start()
            
            # Start a thread to monitor the process completion
            thread = threading.Thread(target=self.monitor_parser_completion, args=(process,))
            thread.daemon = True
            thread.start()
                        
        except Exception as e:   
            self.update_text_area("Failed to trigger the parsing parser.\n")
            self.log_exception("Exception in trigger_parsing_script", e)

    def read_stream(self, stream, is_error):
        """Read the output stream from the subprocess and update the GUI."""
        try:
            for line in iter(stream.readline, ''):
                if line:
                    if is_error:
                        self.update_text_area("[Error] " + line)
                        logging.error(line.strip())
                    else:
                        self.update_text_area(line)
                        logging.info(line.strip())
            stream.close()
        except Exception as e:
            self.log_exception("Exception in read_stream", e)

    def monitor_parser_completion(self, process):
        """Wait for the parser process to complete and then load the parsed sitemap."""
        try:
            process.wait()
            if process.returncode != 0:
                self.update_text_area("Selenium parser exited with errors.\n")
                logging.error("Selenium parser exited with return code %d", process.returncode)
                return
            else:
                self.update_text_area("Selenium parser completed successfully.\n")
                logging.info("Selenium parser completed successfully.")
            
            # Wait until parsed_sitemap.json is available
            timeout = 300  # 5 minutes
            poll_interval = 5  # seconds
            elapsed = 0
            
            while not os.path.exists(self.json_file_path) and elapsed < timeout:
                time.sleep(poll_interval)
                elapsed += poll_interval
                self.update_text_area("Waiting for sitemap parsing to complete...\n")
            
            if not os.path.exists(self.json_file_path):
                self.update_text_area("Failed to retrieve parsed_sitemap.json within the timeout period.\n")
                logging.error("Failed to retrieve parsed_sitemap.json within the timeout period.")
                return
            
            # Read the parsed sitemap
            try:
                with open(self.json_file_path, 'r') as f:
                    self.parsed_data = simplejson.load(f)
                    if not self.parsed_data:
                        self.update_text_area("Parsed sitemap is empty.\n")
                        logging.error("Parsed sitemap is empty")
                        return
                    self.update_text_area("Parsed sitemap loaded successfully.\n")
                    logging.info("Parsed sitemap loaded successfully.")
            except Exception as e:
                self.update_text_area(f"Error loading parsed sitemap: {str(e)}\n")
                logging.error(f"Error loading parsed sitemap: {str(e)}")
                return

            # Update GUI
            self.root.after(0, self.update_button_states)  # Use after to update GUI from thread

        except Exception as e:
            self.update_text_area("Error during Selenium parser execution.\n")
            self.log_exception("Exception in monitor_parser_completion", e)

    def start_autonomous_cycle(self, event=None):
        """Start the autonomous testing cycle."""
        if not os.path.exists(self.json_file_path):
            self.text_area.insert(tk.END, "Please parse sitemap first using the 'Parse Sitemap' button.\n")
            return
        
        # Reset iteration counter when starting new cycle
        self.iteration = 0
        self.autonomous_enabled = True

        # Read Max Iterations from GUI
        try:
            max_iter_text = self.max_iter_var.get().strip()
            if not max_iter_text:
                raise ValueError("Max Iterations input is empty.")
            self.max_iterations = int(max_iter_text)
            if self.max_iterations <= 0:
                raise ValueError("Max Iterations must be a positive integer.")
            logging.info("Set max_iterations to %d" % self.max_iterations)
            self.update_text_area("Max Iterations set to: %d\n" % self.max_iterations)
        except ValueError as e:
            self.text_area.insert(tk.END, "Invalid Max Iterations value. Using default of 5.\n")
            logging.warning("Invalid Max Iterations input: %s. Defaulting to 5.", str(e))
            self.max_iterations = 5  # Default value
            self.max_iter_var.set("5")  # Reset GUI field to default

        # Update button states
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        # Start the autonomous testing cycle in a separate thread
        threading.Thread(target=self.autonomous_testing_cycle, daemon=True).start()

    def stop_autonomous_mode(self, event=None):
        """Stop the autonomous testing cycle."""
        try:
            self.autonomous_enabled = False
            logging.info("Autonomous mode has been stopped by the user.")
            self.text_area.insert(tk.END, "Autonomous mode stopped by the user.\n")
            self.status_var.set("Status: Stopped")
            
            # Shutdown the executor
            self.shutdown_executor()
            
            # Update button states for tkinter
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            
        except Exception as e:
            self.log_exception("Exception while stopping autonomous mode", e)

    def clear_logs(self, event=None):
        """Clear logs and reset iteration counter."""
        try:
            # Clear text area
            self.text_area.delete(1.0, tk.END)
            
            # Clear table 
            for item in self.results_table.get_children():
                self.results_table.delete(item)
                
            # Reset counters
            self.iteration = 0
            self.failed_requests_log = []
            self.total_requests = 0  
            self.successful_requests = 0
            self.failed_requests = 0
            self.vulnerabilities_found = 0
            
            # Update labels
            self.total_var.set(f"Total Requests: {self.total_requests}")
            self.success_var.set(f"Successful Requests: {self.successful_requests}")
            self.failed_var.set(f"Failed Requests: {self.failed_requests}")
            
            # Reset progress bar
            self.progress_var.set(0)
            
            logging.info("Logs have been cleared and iteration counter reset.")
            
        except Exception as e:
            self.log_exception("Exception occurred while clearing logs", e)

    def view_failed_requests(self, event=None):
        """Show logged failed requests in a tkinter text widget."""
        if self.failed_requests_log:
            self.text_area.insert(tk.END, "Failed Requests:\n" + "\n".join(self.failed_requests_log) + "\n") 
            self.text_area.see(tk.END)  # Auto-scroll to bottom
        else:
            self.text_area.insert(tk.END, "No failed requests logged.\n")
            self.text_area.see(tk.END)

    def update_progress_dashboard(self):
        """Update the progress dashboard labels with current counts."""
        # Update tkinter StringVar values to update labels
        self.total_var.set(f"Total Requests: {self.total_requests}")
        self.success_var.set(f"Successful Requests: {self.successful_requests}") 
        self.failed_var.set(f"Failed Requests: {self.failed_requests}")
        
        # Update progress bar percentage
        if self.max_iterations > 0:
            progress = (self.iteration / self.max_iterations) * 100
            self.progress_var.set(progress)

    def log_exception(self, message, e):
        """Log exceptions with error messages and traceback."""
        error_message = message + ": " + str(e)
        logging.error(error_message)
        logging.error("Traceback:\n" + traceback.format_exc())
        
        # Also show error in GUI
        self.text_area.insert(tk.END, "Error: " + error_message + "\n")
        self.text_area.see(tk.END)

    def log_uncaught_exceptions(self, exctype, value, tb):
        """Log uncaught exceptions."""
        logging.error("Uncaught exception:", exc_info=(exctype, value, tb))
        
        # Show error in GUI
        error_msg = f"Uncaught exception: {value}\n"
        self.text_area.insert(tk.END, error_msg)
        self.text_area.see(tk.END)

    def update_text_area(self, text):
        """Update the tkinter text widget with new text."""
        try:
            # Enable the text widget for editing
            self.text_area.config(state=tk.NORMAL)
            
            # Add text to widget
            self.text_area.insert(tk.END, text)
            
            # Auto-scroll to bottom
            self.text_area.see(tk.END)
            
            # Optional: limit buffer size
            if float(self.text_area.index('end-1c')) > 1000:
                # Delete first 100 lines if buffer exceeds 1000 lines
                self.text_area.delete('1.0', '100.end')
                
            # Disable the text widget to prevent user editing
            self.text_area.config(state=tk.DISABLED)
            
            # Force update the GUI
            self.root.update()
            
            logging.debug(f"Text area updated with: {text}")
            
        except Exception as e:
            logging.error(f"Error updating text area: {str(e)}")
            logging.error(traceback.format_exc())

    def log_message(self, message):
        """Append log messages to the text area."""
        self.update_text_area(message + "\n")

    def update_status(self):
        """Update status label based on current state."""
        if not self.target_domain:
            self.status_var.set("Status: Enter target domain to begin")
        else:
            self.status_var.set("Status: Ready for testing")

    def parse_sitemap(self):
        # First get target domain if not set
        if not self.target_domain:
            # Use tkinter dialog to get domain
            domain = simpledialog.askstring("Input", "Enter target domain:")
            if domain:
                self.target_domain = domain.strip()
                self.update_status()
                self.update_text_area(f"Target domain set to: {self.target_domain}\n") 
                self.update_text_area("Beginning crawl of domain...\n")
                self.root.update_idletasks()  # Update GUI immediately
                
                # Start crawling in a separate thread to avoid blocking GUI
                threading.Thread(
                    target=self.trigger_parsing_script,
                    daemon=True
                ).start()
            else:
                self.update_text_area("Please enter a target domain.\n")
                return
        else:
            self.update_text_area("Target domain already set. Restarting crawl...\n")
            threading.Thread(
            target=self.trigger_parsing_script, 
            daemon=True
            ).start()

    def summarize_server_response(self, response):
        """Process response with execution context"""
        try:
            if isinstance(response, dict):
                summary = "=== Response Analysis ===\n"
                summary += f"URL: {response.get('url', 'unknown')}\n"
                summary += f"Status: {response.get('status_code', 'unknown')}\n"

                # Add execution context if available
                exec_log = response.get('execution_log', {})
                if exec_log:
                    summary += "\n=== Execution Context ===\n"
                    
                    # Alert information
                    if exec_log.get('alert_triggered'):
                        summary += f"Alert Triggered: {exec_log.get('alert_text', 'unknown')}\n"
                    
                    # Other execution data
                    if 'events' in exec_log:
                        summary += f"Events Triggered: {len(exec_log['events'])}\n"
                    if 'mutations' in exec_log:
                        summary += f"DOM Mutations: {len(exec_log['mutations'])}\n"
                    if 'network' in exec_log:
                        summary += f"Network Requests: {len(exec_log['network'])}\n"

                # Add response body if available
                if 'body' in response:
                    summary += "\n=== Response Body ===\n"
                    summary += response['body'][:1000] + "...\n" if len(response['body']) > 1000 else response['body']

                return summary
                
            return str(response)

        except Exception as e:
            self.log_exception("Error in summarize_server_response", e)
            return str(response)
        

    def analyze_response_request_pair(self, messageInfo, request_data, response_data):
        try:
            logging.debug("Constructing payload for OpenAI...")
            
            # Extract execution context if available
            execution_context = ""
            if isinstance(response_data, dict) and 'execution_log' in response_data:
                exec_log = response_data['execution_log']
                
                # Format function executions
                executed_functions = exec_log.get('functions', set())
                function_calls = []
                if executed_functions:
                    for func in executed_functions:
                        if isinstance(func, dict):
                            function_calls.append({
                                'function': func.get('function'),
                                'arguments': func.get('arguments'),
                                'stack': func.get('stack')
                            })

                # Format DOM mutations
                mutations = exec_log.get('mutations', [])
                significant_mutations = []
                for mutation in mutations:
                    if mutation.get('addedNodes'):
                        for node in mutation.get('addedNodes', []):
                            if node.get('type') in ['SCRIPT', 'IFRAME', 'IMG', 'OBJECT', 'EMBED']:
                                significant_mutations.append({
                                    'type': node.get('type'),
                                    'html': node.get('html'),
                                    'attributes': node.get('attributes')
                                })

                # Format state changes
                states = exec_log.get('states', [])
                state_changes = []
                if len(states) > 1:  # Compare initial and final states
                    initial_state = states[0]
                    final_state = states[-1]
                    state_changes = {
                        'url_changed': initial_state.get('url') != final_state.get('url'),
                        'dom_elements_delta': final_state.get('dom', {}).get('elements', 0) - 
                                            initial_state.get('dom', {}).get('elements', 0),
                        'scripts_delta': final_state.get('dom', {}).get('scripts', 0) - 
                                    initial_state.get('dom', {}).get('scripts', 0)
                    }

                # Format network activity
                network_requests = exec_log.get('network', [])
                
                # Format events
                events = exec_log.get('events', [])
                
                execution_context = f"""
                === Execution Context Analysis ===
                
                1. Function Executions:
                Total functions called: {len(function_calls)}
                Notable calls: {[f"{call['function']}({', '.join(call['arguments'])})" for call in function_calls]}
                
                2. DOM Modifications:
                Total mutations: {len(mutations)}
                Significant changes: {len(significant_mutations)}
                Details: {significant_mutations}
                
                3. State Changes:
                URL modified: {state_changes.get('url_changed', False)}
                DOM elements delta: {state_changes.get('dom_elements_delta', 0)}
                New scripts loaded: {state_changes.get('scripts_delta', 0)}
                
                4. Network Activity:
                Total requests: {len(network_requests)}
                External URLs: {[req['url'] for req in network_requests if req.get('url', '').startswith('http')]}
                
                5. Events Triggered:
                Total events: {len(events)}
                Types: {set(event['type'] for event in events)}
                
                6. Final State:
                Current URL: {response_data.get('url', 'unknown')}
                Document state: {response_data.get('final_state', {}).get('documentState', 'unknown')}
                """

            messages = [    
                {
                    "role": "system",
                    "content": (
                        "You are a security expert analyzing HTTP requests, responses, and execution patterns. "
                        "Focus on identifying CONFIRMED vulnerabilities based on actual execution evidence."
                        "\n\nAnalysis Guidelines:"
                        "\n1. Execution Evidence:"
                        "\n- Look for concrete proof of successful exploitation in execution logs"
                        "\n- Analyze function calls, DOM mutations, and state changes"
                        "\n- Consider network requests and event triggers"
                        "\n- Evaluate the significance of state changes"
                        "\n- Look for error messages, or other indicators of exploitation"
                        
                        "\n\n2. Confidence Scoring:"
                        "\n- 0.0: No exploitation evidence"
                        "\n- 0.3: Suspicious behavior but inconclusive"
                        "\n- 0.7: Strong indicators with some uncertainty"
                        "\n- 1.0: Definitive proof of successful exploitation"
                        
                        "\n\n3. Exploitation Patterns:"
                        "\n- Function hijacking or unexpected calls"
                        "\n- Suspicious DOM modifications"
                        "\n- Unauthorized state changes"
                        "\n- Anomalous network activity"
                        "\n- Unusual event patterns"
                        
                        "\n\nOutput Format:"
                        "\n1. Execution Analysis"
                        "\n2. Evidence Summary"
                        "\n3. Exploitation Assessment"
                        "\n4. Confidence Score"
                        "\n5. {\"vulnerability_confidence\": X.X}"
                    )
                },
                {
                    "role": "user",
                    "content": (    
                        "Analyze this request/response pair and execution context for CONFIRMED security vulnerabilities:\n\n"
                        "\n- A vulnerability is only CONFIRMED if the response shows clear evidence of successful exploitation"
                        "\n- The mere presence of an attack payload is NOT evidence of vulnerability"
                        "\n- Blocked requests (40x responses) indicate protection, not vulnerability"
                        "\n- Status code of 200 does NOT inherently confirm a vulnerability, nor does it negate it"
                        "\n- Theoretical issues or potential vulnerabilities should be marked as NOT VULNERABLE"
                        "\n- Successful requests with no apparent protective measures do NOT inherently confirm a vulnerability, nor do they negate it"
                        "\n- A vulnerability is confirmed if and only if there is evidence for it in the execution context!"
                        "REQUEST:\n%s\n\n"
                        "EXECUTION CONTEXT:\n%s\n\n"
                        "RESPONSE:\n%s" % (
                            request_data,
                            execution_context,
                            response_data.get('body', '') if isinstance(response_data, dict) else response_data
                        )
                    )
                }
            ]

            payload_dict = {
                "model": "gpt-4o-mini", 
                "temperature": 0.1, 
                "messages": messages
            }
            
            # Use ensure_ascii=False to handle non-ASCII characters
            payload_json = simplejson.dumps(payload_dict, ensure_ascii=False)
            
            # Truncate if too long while maintaining valid JSON structure
            max_length = 50000
            if len(payload_json) > max_length:
                try:
                    data = simplejson.loads(payload_json)
                    if "messages" in data and len(data["messages"]) > 0:
                        last_msg = data["messages"][-1]
                        content = last_msg.get("content", "")
                        if len(content) > max_length - 1000:
                            last_msg["content"] = content[:max_length - 1000] + "..."
                            data["messages"][-1] = last_msg
                        payload_json = simplejson.dumps(data)
                except:
                    payload_json = payload_json[:max_length - 3] + "..."
                    
            def truncate_for_logging(s, max_length=1000):
                if len(s) > max_length:
                    return s[:max_length] + "... (truncated)"
                return s
                
            logging.debug("Payload JSON string created: %s", truncate_for_logging(payload_json))
            return payload_json
                
        except Exception as e:
            self.log_exception("Exception in create_payload", e)
            raise

    def eval_confidence_level(self, response):
        """Parse AEye response and evaluate vulnerability confidence"""
        try:
            try:
                if not response:
                    return 0.0
                    
                # Convert to lowercase for case-insensitive matching
                response = response.lower()
                
                # Extract JSON evaluation with regex - match both formats
                json_match = re.search(r'{\s*"vulnerability_confidence"\s*:\s*(0\.[0-9]|1\.0)\s*}', response.lower())
                if json_match:
                    return float(json_match.group(1)) # Convert string to float and return

            except Exception as e:
                logging.error("Error evaluating confidence level: %s", str(e))
                return 0.0
        except Exception as e:
            logging.error("Error parsing AEye response: %s" % str(e))
            return 0.0

    def safe_encode(self, text):
            """Safely encode text to handle Unicode characters."""
            if text is None:
                return "N/A"
            
            try:
                # If it's already a string, just return it
                if isinstance(text, str):
                    return text
                
                # If it's bytes, decode it
                if isinstance(text, bytes):
                    return text.decode('utf-8', 'replace')
                
                # Convert other types to string
                return str(text)
            except Exception as e:
                logging.error("Encoding error: %s" % str(e))
                return str(text).encode('ascii', 'replace').decode('ascii')

    def extract_full_payload(self, url, parameter):
        """Extract and decode the full payload from a URL parameter"""
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if parameter in params:
                # Get the raw encoded value
                encoded_payload = params[parameter][0]
                
                # Decode it multiple times to handle nested encoding
                decoded_payload = encoded_payload
                previous_payload = None
                
                # Keep decoding until no more changes occur
                while '%' in decoded_payload and decoded_payload != previous_payload:
                    previous_payload = decoded_payload
                    try:
                        decoded_payload = unquote(decoded_payload)
                    except:
                        break
                        
                logging.debug(f"Original payload: {encoded_payload}")
                logging.debug(f"Decoded payload: {decoded_payload}")
                
                return decoded_payload
            return None
            
        except Exception as e:
            logging.error(f"Error extracting payload: {str(e)}")
            return None

    def analyze_with_openai(self, messageInfo, request_data, response_data, actions={}):
        try:
            # Extract full payload if parameters are available
            if actions.get('parameter') and actions.get('endpoint'):
                try:
                    # Parse URL to get query params
                    parsed_url = urlparse(actions['endpoint'])
                    params = parse_qs(parsed_url.query)
                    
                    parameter = actions['parameter']
                    if parameter in params:
                        # Get raw encoded value without parameter name
                        encoded_payload = params[parameter][0]
                        
                        # Decode multiple times to handle nested encoding
                        decoded_payload = encoded_payload
                        previous = None
                        while '%' in decoded_payload and decoded_payload != previous:
                            previous = decoded_payload
                            try:
                                decoded_payload = unquote(decoded_payload)
                            except:
                                break
                                
                        # Update actions with decoded payload
                        # Remove parameter name if present at start of decoded payload
                        if parameter and decoded_payload.startswith(parameter + '='):
                            decoded_payload = decoded_payload[len(parameter)+1:]
                        actions['payload'] = decoded_payload
                        logging.debug(f"Extracted payload: {decoded_payload}")
                        
                        # Also update request_data if it exists 
                        if isinstance(request_data, dict):
                            request_data['payload'] = decoded_payload
                except Exception as e:
                    logging.error(f"Error extracting payload: {str(e)}")

            # Include the payload from actions when building the request summary                    
            request_str = ""
            if actions:
                request_str = (
                    f"=== Request Details ===\n"
                    f"Method: {actions.get('method', 'GET')}\n" 
                    f"Endpoint: {actions.get('endpoint', '')}\n"
                    f"Parameter: {actions.get('parameter', '')}\n"
                    f"Payload: {actions.get('payload', '')}\n"
                )
                
            logging.debug("Creating payload...")
            logging.debug("Response data: %s" % response_data[:200])
            response_summary = self.summarize_server_response(response_data)
            logging.debug("Response summary: %s" % response_summary[:200])
            
            # Pass the enhanced request string to analyze_response_request_pair
            aeye_request_to_openai = self.analyze_response_request_pair(
                messageInfo,
                request_str,
                response_summary
            )
            
            max_length = 50000  # Define maximum length as needed
            if len(aeye_request_to_openai) > max_length:
                aeye_request_to_openai = aeye_request_to_openai[:max_length] + '."}], "model": "gpt-4o-mini"}'
                
            logging.debug("Aeye request to OpenAI length: %d" % len(aeye_request_to_openai))
            aeye_analysis_of_of_response = self.send_request_to_openai(aeye_request_to_openai)
            logging.debug("Aeye analysis of response: %s" % aeye_analysis_of_of_response)
            aeye_parsed_response = self.parse_openai_response(aeye_analysis_of_of_response)
            logging.debug("AEye parsed response: %s" % aeye_parsed_response)
            
            # Get valid response data first
            confidence_level = 0.0
            if aeye_parsed_response:
                confidence_level = self.eval_confidence_level(aeye_parsed_response)
                
            # Track failed payload if confidence is 0.0
            if confidence_level == 0.0:
                request_info = messageInfo.request if hasattr(messageInfo, 'request') else messageInfo

                # Log the full state
                logging.debug("=== Tracking Failed Payload ===")
                logging.debug("Request Info URL: %s" % request_info.get('url', 'unknown'))
                logging.debug("Request Info Method: %s" % request_info.get('method', 'GET'))
                logging.debug("Actions: %s" % actions)

                context = {
                    "method": request_info.get('method', 'GET'),
                    "url": str(request_info.get('url', '')),
                    "parameter": actions.get("parameter"),
                    "form": actions.get("form")
                }
                
                logging.debug("Found failed payload (confidence = 0.0):")
                logging.debug("Context: %s" % context)
                logging.debug("Payload: %s" % actions.get('payload'))
                
                #self.payload_tracker.track_failure(
                #    context=context,
                #    payload=actions.get("payload"),
                #    response=response_data
                #)

            # Extract URL from messageInfo consistently
            request_url = (messageInfo.request.url if hasattr(messageInfo, 'request') 
                         else messageInfo.get('url', 'unknown') if isinstance(messageInfo, dict)
                         else 'unknown')
            
            # Use action method if available
            method = actions.get('method', 'GET')

            insights = (
                "=== AEye Analysis ===\n"
                "%s\n" # Include request details
                "Response Summary: %s\n"
                "Analysis: %s\n"
                "Vulnerability confidence level: %s" % (
                    request_str,
                    response_summary, 
                    aeye_parsed_response,
                    confidence_level
                )
            )
            logging.debug("Insights: %s" % insights)

            # Update counters and table
            self.total_requests += 1
            
            try:
                table_payload = actions.get('payload')
                table_summary = aeye_parsed_response if aeye_parsed_response else "No analysis available"
                table_status = f"Vulnerability confidence level: {confidence_level:.2f}"
                
                if confidence_level == 1.0:
                    self.successful_requests += 1
                    vuln_data = {
                    "method": method,
                    "endpoint": actions.get('endpoint'),
                    "parameter": actions.get('parameter'),
                    "subdirectory": actions.get('subdirectory'),
                    "payload": actions.get('payload'),
                    "confidence": confidence_level,
                    "analysis": table_summary,
                    "request": actions.get('request')  # Added full request
                    }
                    self.vulnerabilities_to_write.append(vuln_data)
                else:
                    self.failed_requests += 1
                # Update table with sanitized data
                # Build full request details string
                request_details = f"""
                                    REQUEST:
                                    Method: {actions.get('method', 'GET')}
                                    URL: {actions.get('endpoint', 'N/A')}
                                    Parameter: {actions.get('parameter', 'N/A')} 
                                    Payload: {actions.get('payload', 'N/A')}
                                    """

                # Add form details if present
                if actions.get('form'):
                    form = actions['form']
                    request_details += f"""
                                    Form Details:
                                    Action: {form.get('action', 'N/A')}
                                    Method: {form.get('method', 'N/A')}
                                    Inputs: {', '.join(input.get('name', 'unnamed') for input in form.get('inputs', []))}
                                    """

                self.update_autonomous_table(
                    self.safe_encode(request_details),
                    self.safe_encode(actions.get('endpoint')),
                    self.safe_encode(table_payload) if table_payload else "N/A",
                    self.safe_encode(f"{table_summary}\n RESPONSE SUMMARY: \n{response_summary}"), 
                    self.safe_encode(table_status)
                )


            except Exception as e:
                logging.error("Failed to update autonomous table: %s" % str(e))

            self.update_progress_dashboard()
            return insights

        except Exception as e:
            self.log_exception("Exception occurred during OpenAI analysis", e)
            return "OpenAI Analysis Error"

    def create_payload(self, analysis_data):
        try:
            if not analysis_data:
                return None
            
            # Get context safely with defaults
            context = analysis_data.get("context", {})
            parameter_type = context.get("parameter_purpose")
            parameter_types = parameter_type.split("+") if parameter_type else ["general"]
            
            # Get required parameters
            required_params = context.get("required_parameters", [])
            form_context = context.get("form_context", {})
            
            # Get failed payload history
            try:
                failed_history = self.payload_tracker.format_for_ai_prompt(analysis_data)
                logging.debug("Failed history for AI prompt: %s" % failed_history)
            except Exception as e:
                logging.error("Error getting failed history: %s" % str(e))
                failed_history = "No previous failures recorded"

            logging.debug("=== Creating New Payload ===")
            logging.debug("Analysis Data Structure: %s" % analysis_data)
            logging.debug("Required Parameters: %s" % required_params)
            
            # Enhanced context details with required parameters info
            context_details = (
                "Target Analysis:\n"
                "- Parameter Type: %s\n"
                "- Context Types: %s\n"
                "- Risk Level: %s\n"
                "- Operation: %s\n"
                "- Environment: %s\n\n"
                
                "Endpoint Details:\n"
                "- Full URL: %s\n"
                "- HTTP Method: %s\n"
                "- Required Parameters: %s\n"  # Added this line
                "- Path Structure: %s\n"
                "- Content Type: %s\n\n"
                
                "Security Context:\n"
                "- Auth Required: %s\n"
                "- Admin Interface: %s\n"
                "- File Operations: %s\n"
                "- Data Sensitivity: %s\n"
                "- Security Controls: %s\n\n"
                
                "Form Context:\n"  # Added form context section
                "- Form Purpose: %s\n"
                "- Risk Level: %s\n"
                "- Security Features: %s\n"
                
                "Previous Attempts:\n"
                "- Failed Techniques: %s\n"
                "- Blocked Patterns: %s\n"
                "- WAF Reactions: %s\n"
            ) % (
                parameter_types[0] if parameter_types else 'unknown',
                ', '.join(parameter_types[1:]) if len(parameter_types) > 1 else 'none',
                'HIGH' if any('high_risk' in t for t in parameter_types) else 'MEDIUM',
                [t for t in parameter_types if 'operation' in t],
                context.get('environment', 'unknown'),
                analysis_data.get('endpoint', 'unknown'),
                analysis_data.get('method', 'GET'),
                ', '.join(required_params) if required_params else 'none',  # Added required params
                analysis_data.get('subdirectory', '/'),
                context.get('content_type', 'unknown'),
                'auth_context' in parameter_types,
                'admin_context' in parameter_types,
                'file_operation' in parameter_types,
                bool([t for t in parameter_types if 'high_risk' in t]),
                context.get('security_controls', []),
                form_context.get('form_purpose', 'unknown') if form_context else 'N/A',
                form_context.get('risk_level', 'unknown') if form_context else 'N/A',
                form_context.get('security_features', {}) if form_context else 'N/A',
                context.get('failed_techniques', []),
                context.get('blocked_patterns', []),
                context.get('waf_reactions', [])
            )

            messages = [    
                {
                    "role": "system",
                    "content": (
                        "You are an elite security researcher specializing in advanced payload generation."
                        "\n\nCapabilities:"
                        "\n- Deep understanding of web vulnerabilities"
                        "\n- Expert in WAF/security control bypass techniques"
                        "\n- Advanced knowledge of context-specific attack vectors"
                        "\n You specialize in developing complex, smart, and highly effective, security testing payloads."
                        "\n\nOutput Format Rules:"
                        "\nYou must respond with a JSON object in the following format:"
                        "\n```json"
                        "\n{"
                        "\n    \"parameter_name\": \"payload_value\","
                        "\n    \"parameter_name2\": \"payload_value2\""
                        "\n}"
                        "\n```"
                        "\nWhere parameter_name matches the required parameter names exactly."
                    )
                },
                {
                    "role": "user", 
                    "content": (
                        "Generate advanced, complex, highly effective, security test payloads for this endpoint."
                        "\n\nContext Information:\n%s"
                        #"\n\nPreviously Failed Payloads:\n%s"
                        "\n\nRequirements:"
                        "\n1. Generate payloads for these REQUIRED parameters: %s"
                        "\n2. Each parameter must have exactly one payload string"
                        "\n3. Parameter names in the response must match exactly"
                        "\n4. Response must be valid JSON wrapped in ```json``` tags"
                        "\n5. Create creative payloads to bypass security controls"
                    ) % (
                        context_details, 
                        #failed_history,
                        ', '.join(required_params) if required_params else 'single parameter mode'
                    )
                }
            ]

            logging.debug("Context length: %d" % len(context_details))
            logging.debug("Failed history length: %d" % len(failed_history))

            return {
                "model": "gpt-4o-mini",
                "temperature": 2,
                "messages": messages,
                "max_tokens": 100
            }

        except Exception as e:
            logging.error("Error creating payload: %s" % str(e))
            logging.error("Analysis data: %s" % analysis_data)
            return None
        
    def send_request_to_openai(self, data):
        try:
            logging.debug("Sending request to OpenAI API...")
            
            if not self.api_key:
                logging.error("No API key configured")
                messagebox.showerror("Error", "Please configure your OpenAI API key first.")
                return None

            # Convert data to proper format if needed
            if isinstance(data, str):
                try:
                    json_data = simplejson.loads(data)
                    data = simplejson.dumps(json_data)
                except:
                    logging.error("Invalid JSON string provided: %s" % data)
                    return None
            elif isinstance(data, dict):
                data = simplejson.dumps(data)
            else:
                logging.error("Invalid data type: %s" % type(data))
                return None

            if isinstance(data, str):
                data = data.encode('utf-8')

            if not data:
                logging.error("Empty data provided")
                return None

            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json"
            }

            url = "https://api.openai.com/v1/chat/completions"
            
            max_retries = 3
            retry_delay = 2

            for attempt in range(max_retries):
                try:
                    response = requests.post(
                    url,
                    headers=headers,
                    data=data,
                    timeout=30
                    )
                    
                    if response.status_code == 200:
                        return response.text
                    else:
                        logging.error("Attempt %d: Status code %d" % (attempt + 1, response.status_code))
                        logging.error("Error response: %s" % response.text)
                    
                    if attempt < max_retries - 1:
                        logging.debug("Retrying in %d seconds..." % retry_delay)
                        time.sleep(retry_delay)
                    
                except Exception as e:
                    logging.error("Request attempt %d failed: %s" % (attempt + 1, str(e)))
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)

                return None

        except Exception as e:
            logging.error("Error in send_request_to_openai: %s" % str(e))
            return None

    def parse_openai_response(self, response):
        try:
            if not response:
                logging.error("Empty response received from OpenAI")
                return None

            # Ensure response is string
            if not isinstance(response, (str, bytes)):
                logging.error("Invalid response type: %s" % type(response))
                return None

            # Parse JSON response
            try:
                response_data = simplejson.loads(response)
                
                if 'choices' not in response_data:
                    logging.error("No choices in response")
                    return None
                    
                content = response_data['choices'][0]['message']['content']
                return content.strip()
                
            except simplejson.JSONDecodeError:
                logging.error("Failed to parse response JSON")
                return None
                
        except Exception as e:
            logging.error("Error parsing OpenAI response: %s" % str(e))
            return None

    def analyze_endpoint_for_injection(self, endpoint):
        if not endpoint:
            logging.error("analyze_endpoint_for_injection received None endpoint")
            return None

        try:
            url = endpoint.get("url", "")
            if not url:
                logging.error("No URL found in endpoint data")
                return None
                
            parsed_url = urlparse(url)
            logging.debug("Analyzing endpoint: %s", str(url))
            
            # Initialize endpoint data structure
            endpoint_data = {
                "url": url,
                "path": parsed_url.path,
                "query_params": dict(parse_qs(parsed_url.query)) if parsed_url.query else {},
                "forms": endpoint.get("forms", []),
                "params": endpoint.get("data", {}),
                "method": endpoint.get("method", "GET"),
                "response_data": None
            }

            # Get parameters to test and form context
            params_to_test = []
            form_contexts = []
            selected_param = None
            param_type = None
            related_params = []
            required_params = []  # New: Track required parameters
            
            # Get method from endpoint data
            method = "GET"  # Default method
            if "data" in endpoint:
                # Iterate through the methods in order of preference (POST first)
                for http_method in ["POST", "GET"]:
                    method_data = endpoint["data"].get(http_method, {})
                    
                    # Check forms first for POST
                    if http_method == "POST" and method_data.get("forms"):
                        # Get method from the last form
                        last_form = method_data["forms"][-1]
                        if last_form.get("method"):
                            method = last_form["method"].upper()
                            # New: Extract required parameters from form
                            required_params = [
                                input_field.get("name") 
                                for input_field in last_form.get("inputs", [])
                                if input_field.get("required", False)
                            ]
                            break
                    
                    # Check if method is available
                    if method_data.get("available"):
                        method = http_method
                        break

            if endpoint_data["method"] == "GET":
                params = endpoint.get("data", {}).get("GET", {}).get("parameters", [])
                if params:
                    params_to_test = params
                    required_params = params  # For GET, consider all parameters as required
            elif endpoint_data["method"] == "POST":
                post_data = endpoint.get("data", {}).get("POST", {})
                if post_data.get("parameters"):
                    params_to_test = post_data["parameters"]
                elif post_data.get("forms"):
                    selected_form = random.choice(post_data["forms"])
                    params_to_test = [input_field.get("name") for input_field in selected_form.get("inputs", [])]
                    # New: Get required parameters from form
                    required_params = [
                        input_field.get("name") 
                        for input_field in selected_form.get("inputs", [])
                        if input_field.get("required", False)
                    ]
                    # Analyze the form context
                    form_context = self.analyze_form_context(selected_form)
                    if form_context:
                        form_contexts.append(form_context)

            # Select parameter and get related info
            if params_to_test:
                # New: Prefer required parameters when selecting
                if required_params:
                    selected_param = random.choice(required_params)
                else:
                    selected_param = random.choice(params_to_test)
                param_type = self.infer_parameter_type(selected_param, parsed_url.path)
                related_params = self.find_related_parameters(selected_param, params_to_test)
            else:
                logging.debug("No parameters found for testing")

            # Create analysis data with complete context
            analysis_data = {
                "endpoint": endpoint_data["url"],
                "method": method,
                "parameter": selected_param,
                "subdirectory": parsed_url.path,
                "context": {
                    "parameter_purpose": param_type,
                    "endpoint_category": self.infer_endpoint_category(parsed_url.path),
                    "related_parameters": related_params,
                    "form_context": form_contexts[0] if form_contexts else None,
                    "all_parameters": params_to_test,
                    "required_parameters": required_params,  # New: Add required parameters to context
                    "request_method": endpoint_data["method"],
                    "is_api": any(api_term in parsed_url.path.lower() for api_term in ['api', 'v1', 'v2', 'rest']),
                    "has_file_operations": any(file_term in parsed_url.path.lower() for file_term in ['upload', 'download', 'file']),
                    "security_indicators": {
                        "has_auth": any(auth_term in parsed_url.path.lower() for auth_term in ['auth', 'login', 'token']),
                        "is_admin": any(admin_term in parsed_url.path.lower() for admin_term in ['admin', 'manage', 'dashboard']),
                        "has_sensitive_terms": any(sensitive_term in parsed_url.path.lower() for sensitive_term in ['password', 'secret', 'key', 'token'])
                    }
                }
            }

            logging.debug("Generated analysis data with context: %s", str(analysis_data))
            return analysis_data

        except Exception as e:
            logging.error("Error analyzing endpoint for injection: %s" % str(e))
            return None
        
    def infer_parameter_type(self, param_name, path):
        """Enhanced parameter type inference combining parameter naming, path context,
        security context, and operational context"""
        param_lower = param_name.lower()
        path_lower = path.lower()
        path_components = [p.lower() for p in path.split('/') if p]
        
        # Define path contexts that influence parameter interpretation
        path_contexts = {
            'file_context': ['upload', 'download', 'file', 'document', 'image'],
            'auth_context': ['auth', 'login', 'register', 'password', 'security'],
            'admin_context': ['admin', 'manage', 'dashboard', 'control'],
            'user_context': ['profile', 'user', 'account', 'preferences'],
            'payment_context': ['payment', 'billing', 'checkout', 'subscribe']
        }

        # Check active contexts
        active_contexts = []
        for context_name, context_terms in path_contexts.items():
            if any(term in path_components for term in context_terms):
                active_contexts.append(context_name)

        # Parameter type definitions with enhanced categories
        param_types = {
            'identifier': ['id', 'uuid', 'guid', 'ref', 'key'],
            'file_operation': ['file', 'upload', 'document', 'image'],
            'authentication': ['token', 'auth', 'key', 'password'],
            'payment': ['payment', 'price', 'amount', 'card'],
            'user_data': ['name', 'email', 'phone', 'address']
        }

        # Initialize result types
        result_types = []
        
        # Add parameter type if found
        for type_name, terms in param_types.items():
            if any(term in param_lower for term in terms):
                result_types.append(type_name)
                break

        # Add context types and convert to list to ensure JSON serialization
        result_types = list(set(result_types).union(set(active_contexts)))

        # Add high-risk combinations
        if 'file_operation' in result_types and 'auth_context' in active_contexts:
            result_types.append('high_risk_file')
        if 'identifier' in result_types and 'admin_context' in active_contexts:
            result_types.append('high_risk_admin')

        # Add operation context
        if any(op in path_lower for op in ['get', 'view', 'show']):
            result_types.append('read_operation')
        elif any(op in path_lower for op in ['post', 'create', 'add']):
            result_types.append('write_operation')
        elif any(op in path_lower for op in ['put', 'update', 'edit']):
            result_types.append('modify_operation')
        elif any(op in path_lower for op in ['delete', 'remove']):
            result_types.append('delete_operation')

        return '+'.join(result_types) if result_types else 'general'

    def infer_endpoint_category(self, path):
        """Infer the general category of the endpoint"""
        path_components = [p.lower() for p in path.split('/') if p]
        
        # Authentication & User Management
        if any(auth in path_components for auth in [
            'auth', 'login', 'logout', 'register', 'signup', 'signin',
            'password', 'reset', 'verify', 'confirm', 'token', 'session',
            'oauth', 'sso', 'saml', 'identity', 'account', 'profile'
        ]):
            return "authentication"
            
        # API & Integration
        elif any(api in path_components for api in [
            'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'soap', 'rpc',
            'webhook', 'callback', 'integration', 'service', 'endpoint',
            'interface', 'gateway', 'bridge', 'connector', 'sync'
        ]):
            return "api"
            
        # Administrative
        elif any(admin in path_components for admin in [
            'admin', 'manage', 'dashboard', 'console', 'control', 'system',
            'settings', 'config', 'monitor', 'report', 'analytics', 'metrics',
            'audit', 'log', 'security', 'permission', 'role', 'user'
        ]):
            return "administrative"
            
        # File Operations
        elif any(file in path_components for file in [
            'file', 'upload', 'download', 'document', 'image', 'media',
            'storage', 'cdn', 'asset', 'resource', 'static', 'public',
            'private', 'share', 'backup', 'archive', 'export', 'import'
        ]):
            return "file_operations"
            
        # Payment & Transactions
        elif any(payment in path_components for payment in [
            'payment', 'transaction', 'order', 'checkout', 'cart', 'billing',
            'invoice', 'subscription', 'pricing', 'plan', 'credit', 'debit',
            'refund', 'cancel', 'purchase', 'pay', 'wallet', 'balance'
        ]):
            return "payment"
            
        # Content Management
        elif any(content in path_components for content in [
            'content', 'post', 'article', 'blog', 'news', 'page', 'template',
            'theme', 'layout', 'design', 'editor', 'draft', 'publish', 'cms',
            'category', 'tag', 'comment', 'review', 'rating', 'feedback'
        ]):
            return "content"
            
        # User Data
        elif any(user in path_components for user in [
            'user', 'customer', 'client', 'member', 'contact', 'profile',
            'account', 'personal', 'preference', 'setting', 'notification',
            'message', 'inbox', 'mail', 'communication', 'subscription'
        ]):
            return "user_data"
            
        # Analytics & Reporting
        elif any(analytics in path_components for analytics in [
            'analytics', 'report', 'statistics', 'metrics', 'dashboard',
            'insight', 'tracking', 'monitor', 'log', 'audit', 'activity',
            'performance', 'usage', 'trend', 'analysis', 'visualization'
        ]):
            return "analytics"
            
        # Search & Discovery
        elif any(search in path_components for search in [
            'search', 'find', 'query', 'filter', 'browse', 'explore',
            'discover', 'lookup', 'suggest', 'recommend', 'similar',
            'related', 'category', 'directory', 'index', 'catalog'
        ]):
            return "search"

        return "general"

    def find_related_parameters(self, target_param, all_params):
        """Find parameters that might be related to the target parameter"""
        related = {
            "naming_related": [],
            "context_related": [],
            "type_related": []
        }
        
        target_base = re.sub(r'[0-9_-]', '', target_param.lower())
        
        # Common parameter groupings
        param_groups = {
            "credentials": ['username', 'password', 'email'],
            "pagination": ['page', 'size', 'offset', 'limit'],
            "sorting": ['sort', 'order', 'direction'],
            "filters": ['filter', 'query', 'search'],
            "dates": ['date', 'start', 'end', 'from', 'to']
        }
        
        for param in all_params:
            if param == target_param:
                continue
                
            param_base = re.sub(r'[0-9_-]', '', param.lower())
            
            # Check for naming relationships
            if param_base.startswith(target_base) or target_base.startswith(param_base):
                related["naming_related"].append(param)
                
            # Check for context relationships
            for group_name, group_params in param_groups.items():
                if any(term in target_param.lower() for term in group_params):
                    if any(term in param.lower() for term in group_params):
                        related["context_related"].append({
                            "param": param,
                            "group": group_name
                        })
        
        return related
    

    def analyze_form_context(self, form):
        """Enhanced analysis of form context based on its inputs"""
        if not form.get('inputs'):
            return None
            
        form_analysis = {
            "parameters": [],
            "input_types": {},
            "security_features": {},
            "validation_hints": {},
            "field_relationships": {},
            "form_purpose": "unknown",
            "risk_level": "low",
            "data_sensitivity": [],
            "attack_surface": {},
            "context_hints": []
        }
        
        input_fields = form.get('inputs', [])
        
        sensitive_patterns = {
            "pii": ["name", "email", "phone", "address", "ssn", "dob", "birth"],
            "financial": ["card", "credit", "payment", "account", "bank", "invoice", "price"],
            "auth": ["password", "token", "key", "secret", "auth", "jwt", "api"],
            "system": ["file", "path", "command", "exec", "upload", "system", "admin"],
            "database": ["query", "sql", "select", "insert", "update", "delete"]
        }
        
        attack_surfaces = {
            "injection": [],
            "upload": [],
            "auth_bypass": [],
            "data_leak": [],
            "logic_flaw": [],
            "csrf": []
        }

        for field in input_fields:
            field_name = field.get('name', '')
            field_type = field.get('type', 'text')
            
            field_info = {
                "type": field_type,
                "required": field.get('required', False),
                "attributes": {},
                "risk_factors": [],
                "potential_attacks": [],
                "context_category": self.determine_field_context(field_name, field_type)
            }
            
            # Attribute analysis
            for attr in ['pattern', 'minlength', 'maxlength', 'min', 'max', 'required']:
                if attr in field:
                    field_info["attributes"][attr] = field[attr]
                    if attr.startswith('on') or attr in ['src', 'href', 'action']:
                        field_info["risk_factors"].append("client_side_event")
                        attack_surfaces["injection"].append(field_name)

            # Sensitivity and risk analysis
            for category, patterns in sensitive_patterns.items():
                if any(pattern in field_name for pattern in patterns):
                    field_info["risk_factors"].append("sensitive_%s" % category)
                    form_analysis["data_sensitivity"].append(category)

            # Attack surface analysis based on field type and context
            field_info["potential_attacks"] = self.determine_potential_attacks(field_type, field_name, field_info["context_category"])
            

            form_analysis["parameters"].append({
                "name": field_name,
                "info": field_info
            })
            
            if field_type not in form_analysis["input_types"]:
                form_analysis["input_types"][field_type] = []
            form_analysis["input_types"][field_type].append({
                "name": field_name,
                "context": field_info["risk_factors"]
            })

        # Security features analysis
        form_analysis["security_features"] = self.analyze_security_features(input_fields)
        
        # Risk level determination
        form_analysis["risk_level"] = self.determine_risk_level(form_analysis, attack_surfaces)
        
        # Form purpose analysis
        form_analysis["form_purpose"] = self.determine_form_purpose(form, form_analysis)
        
        # Field relationships
        form_analysis["field_relationships"] = self.analyze_field_relationships(input_fields)
        
        # Validation analysis
        form_analysis["validation_hints"] = self.analyze_validation_rules(input_fields)
        
        form_analysis["attack_surface"] = attack_surfaces
        
        return form_analysis

    def determine_field_context(self, field_name, field_type):
        """Determine the context category of a field"""
        context_patterns = {
            "authentication": ["user", "pass", "auth", "login", "token"],
            "personal": ["name", "email", "phone", "address", "birth"],
            "financial": ["payment", "card", "price", "amount", "currency"],
            "system": ["file", "upload", "path", "command", "admin"],
            "search": ["search", "query", "filter", "find"],
            "metadata": ["description", "title", "tags", "category"]
        }
        
        field_name = field_name.lower()
        
        for context, patterns in context_patterns.items():
            if any(pattern in field_name for pattern in patterns):
                return context
                
        return "general"

    def determine_potential_attacks(self, field_type, field_name, context):
        """Determine potential attacks based on field type and context"""
        attacks = []
        
        type_attacks = {
            "text": ["xss", "sqli", "command_injection"],
            "password": ["auth_bypass", "weak_password"],
            "file": ["upload_bypass", "path_traversal", "rce"],
            "hidden": ["parameter_tampering", "csrf"],
            "email": ["email_injection", "validation_bypass"],
            "number": ["integer_overflow", "type_confusion"],
            "url": ["ssrf", "open_redirect"]
        }
        
        context_attacks = {
            "authentication": ["auth_bypass", "session_fixation"],
            "personal": ["data_exposure", "pii_leak"],
            "financial": ["business_logic", "race_condition"],
            "system": ["rce", "path_traversal"],
            "search": ["sqli", "nosql_injection"],
            "metadata": ["stored_xss", "template_injection"]
        }
        
        attacks.extend(type_attacks.get(field_type, []))
        attacks.extend(context_attacks.get(context, []))
        
        return list(set(attacks))  # Remove duplicates

    def analyze_security_features(self, input_fields):
        """Analyze security features present in the form"""
        return {
            "has_csrf_token": any('csrf' in field.get('name', '').lower() for field in input_fields),
            "has_captcha": any('captcha' in field.get('name', '').lower() for field in input_fields),
            "has_password": any(field.get('type') == 'password' for field in input_fields),
            "has_file_upload": any(field.get('type') == 'file' for field in input_fields),
            "has_hidden_fields": any(field.get('type') == 'hidden' for field in input_fields),
            "has_auth_tokens": any('token' in field.get('name', '').lower() for field in input_fields),
            "has_api_keys": any('key' in field.get('name', '').lower() for field in input_fields),
            "has_recaptcha": any('g-recaptcha' in str(field.get('class', '')) for field in input_fields)
        }

    def determine_risk_level(self, form_analysis, attack_surfaces):
        """Determine overall risk level of the form"""
        risk_scores = {
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        # High-risk indicators
        if form_analysis["security_features"]["has_file_upload"]:
            risk_scores["high"] += 1
        if "financial" in form_analysis["data_sensitivity"]:
            risk_scores["high"] += 1
        if len(attack_surfaces.get("injection", [])) > 0:
            risk_scores["high"] += 1
            
        # Medium-risk indicators
        if form_analysis["security_features"]["has_password"]:
            risk_scores["medium"] += 1
        if "pii" in form_analysis["data_sensitivity"]:
            risk_scores["medium"] += 1
        if len(attack_surfaces.get("auth_bypass", [])) > 0:
            risk_scores["medium"] += 1
            
        # Determine final risk level
        if risk_scores["high"] > 0:
            return "high"
        elif risk_scores["medium"] > 0:
            return "medium"
        return "low"

    def determine_form_purpose(self, form, form_analysis):
        """Determine the purpose of the form based on its characteristics"""
        action = form.get('action', '').lower()
        input_types = form_analysis["input_types"]
        security_features = form_analysis["security_features"]
        
        purpose_indicators = {
            "authentication": {
                "patterns": ["login", "signin", "auth"],
                "required_fields": ["password"],
                "features": ["has_csrf_token"]
            },
            "registration": {
                "patterns": ["register", "signup", "create"],
                "required_fields": ["email", "password"],
                "features": ["has_csrf_token"]
            },
            "file_upload": {
                "patterns": ["upload", "file"],
                "required_fields": ["file"],
                "features": ["has_file_upload"]
            },
            "payment": {
                "patterns": ["payment", "checkout", "order"],
                "required_fields": [],
                "features": []
            },
            "search": {
                "patterns": ["search", "find", "filter"],
                "required_fields": [],
                "features": []
            },
            "contact": {
                "patterns": ["contact", "feedback", "support"],
                "required_fields": ["email"],
                "features": []
            }
        }
        
        for purpose, indicators in purpose_indicators.items():
            if (any(pattern in action for pattern in indicators["patterns"]) or
                all(field in str(input_types).lower() for field in indicators["required_fields"]) or
                all(security_features.get(feature, False) for feature in indicators["features"])):
                return purpose
                
        return "unknown"

    def analyze_field_relationships(self, input_fields):
        """Analyze relationships between form fields"""
        relationships = {}
        
        for field in input_fields:
            field_name = field.get('name', '')
            if not field_name:
                continue
                
            related_fields = []
            
            # Find fields that might be related
            for other_field in input_fields:
                other_name = other_field.get('name', '')
                if other_name and other_name != field_name:
                    # Check for common prefixes/suffixes
                    if (field_name.startswith(other_name) or 
                        other_name.startswith(field_name) or
                        field_name.endswith(other_name) or
                        other_name.endswith(field_name)):
                        related_fields.append({
                            "name": other_name,
                            "relationship_type": "naming"
                        })
                        
                    # Check for common pairs
                    if (("user" in field_name and "pass" in other_name) or
                        ("first" in field_name and "last" in other_name) or
                        ("min" in field_name and "max" in other_name)):
                        related_fields.append({
                            "name": other_name,
                            "relationship_type": "logical_pair"
                        })
            
            if related_fields:
                relationships[field_name] = related_fields
                
        return relationships

    def analyze_validation_rules(self, input_fields):
        """Analyze validation rules for form fields"""
        validation_rules = {}
        
        for field in input_fields:
            field_name = field.get('name', '')
            if not field_name:
                continue
                
            rules = {}
            
            # HTML5 validation attributes
            for attr in ['pattern', 'minlength', 'maxlength', 'min', 'max', 'required']:
                if attr in field:
                    rules[attr] = field[attr]
                    
            # Type-specific validation
            field_type = field.get('type', 'text')
            if field_type in ['email', 'url', 'number', 'tel']:
                rules['format'] = field_type
                
            # Class-based validation hints
            if 'class' in field:
                classes = field['class'].lower()
                for validator in ['required', 'email', 'numeric', 'alphanumeric', 'phone']:
                    if validator in classes:
                        rules['class_validation'] = validator
                        
            if rules:
                validation_rules[field_name] = rules
                
        return validation_rules

    def make_initial_request(self, endpoint_data):
        """Make an initial request to gather response data"""
        try:
            url = endpoint_data["url"]
            parsed_url = urlparse(url)

            # Use the actual method from the endpoint
            method = endpoint_data.get("method", "GET")

            # Build headers dictionary
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*",
                "Connection": "close",
                "hackerone": "thevinci"
            }

            # Add any parameters from the endpoint
            data = None
            if method == "POST" and endpoint_data.get("params"):
                data = endpoint_data["params"]
                headers["Content-Type"] = "application/x-www-form-urlencoded"

            logging.debug("Making initial request to: %s" % url)

            # Send the request with error handling using requests library
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=data,
                    verify=False, # Skip SSL verification
                    timeout=30
                )
                return response

            except requests.exceptions.RequestException as e:
                logging.error("Error making initial request: %s" % str(e))
                return None

        except Exception as e:
            logging.error("Error constructing initial request: %s" % str(e))
            return None

    def create_http_service(self, parsed_url):
        """Helper function to get URL scheme and port"""
        # Extract components from parsed URL
        protocol = parsed_url.scheme
        host = parsed_url.hostname
        port = parsed_url.port
        
        # Set default port if none specified
        if port is None:
            port = 443 if protocol == "https" else 80

        # Return standardized URL info dictionary
        return {
            "host": host,
            "port": port,
            "protocol": protocol,
            "url": f"{protocol}://{host}:{port}"
        }

    def extract_suggestions(self, insights):
        logging.debug("Extracting suggestions from insights...")
        suggested_actions = []
        try:
            pattern = r'```json\s*(\{.*?\})\s*```'
            matches = re.findall(pattern, insights, re.DOTALL)
            if matches:
                json_str = matches[-1]
                logging.debug("Extracted JSON string from insights.")
                try:
                    data = simplejson.loads(json_str)
                except simplejson.JSONDecodeError as e:
                    logging.error("Failed to parse JSON from insights: " + str(e))
                    return suggested_actions
                suggestions = data.get("suggested_payloads", [])
                if isinstance(suggestions, list):
                    for suggestion in suggestions:
                        if isinstance(suggestion, str):
                            suggested_actions.append(suggestion)
                        elif isinstance(suggestion, dict) and 'form' in suggestion:
                            form_data_str = 'FORM::' + simplejson.dumps(suggestion['form'])
                            suggested_actions.append(form_data_str)
                            logging.debug("Extracted form suggestion: " + form_data_str)
                    logging.debug("Extracted suggested actions: " + str(suggested_actions))
                else:
                    logging.warning("suggested_payloads is not a list.")
            else:
                logging.debug("No JSON-formatted suggested_payloads found in insights.")
        except Exception as e:
            self.log_exception("Exception in extract_suggestions", e)
        return suggested_actions
    
    def generate_and_send_requests(self, http_service, actions=None):
        """Generate and send HTTP requests using Selenium with dynamic execution monitoring."""
        try:
            if actions is None:
                actions = {}
            
            method = actions.get('method', 'GET').upper()
            payload = actions.get('payload', '')
            endpoint = actions.get('endpoint', '')
            parameter = actions.get('parameter', '')

            if not self.browser:
                self.browser = self.setup_headless_browser()
                if not self.browser:
                    logging.error("Failed to initialize browser")
                    return []

            # Generic execution monitoring script
            monitor_script = """
            try {
                // Initialize logging object
                window.executionLog = {
                    events: [],
                    mutations: [],
                    scripts: [],
                    states: [],
                    functions: new Set(),
                    network: []
                };

                // Safe state capture function
                window.executionLog.captureState = function() {
                    try {
                        let state = {
                            timestamp: Date.now(),
                            url: window.location.href,
                            documentState: document.readyState,
                            dom: {
                                elements: document.getElementsByTagName('*').length,
                                scripts: document.scripts.length,
                                iframes: document.getElementsByTagName('iframe').length,
                                forms: document.forms.length
                            }
                        };

                        // Safely try to get cookies
                        try {
                            state.cookies = window.location.protocol === 'data:' ? 
                                'N/A (data: URL)' : document.cookie;
                        } catch(e) {
                            state.cookies = 'Error: ' + e.message;
                        }

                        // Safely try to get storage
                        try {
                            state.storage = {
                                local: Object.keys(localStorage),
                                session: Object.keys(sessionStorage)
                            };
                        } catch(e) {
                            state.storage = {error: e.message};
                        }

                        return state;
                    } catch(e) {
                        return {
                            error: e.message,
                            timestamp: Date.now()
                        };
                    }
                };

                // Safe function monitoring
                try {
                    ['eval', 'alert', 'confirm', 'prompt', 'setTimeout', 'setInterval'].forEach(function(func) {
                        if (window[func]) {
                            let original = window[func];
                            window[func] = function() {
                                try {
                                    window.executionLog.functions.add({
                                        function: func,
                                        arguments: Array.from(arguments).map(String),
                                        timestamp: Date.now(),
                                        stack: new Error().stack
                                    });
                                } catch(e) {}
                                return original.apply(this, arguments);
                            };
                        }
                    });
                } catch(e) {
                    console.error('Function monitoring setup failed:', e);
                }

                // Safe event monitoring
                try {
                    window.addEventListener('error', function(e) {
                        window.executionLog.events.push({
                            type: 'error',
                            message: e.message,
                            timestamp: Date.now()
                        });
                    }, true);

                    ['load', 'unload', 'message', 'error', 'click', 'submit', 'input'].forEach(function(eventType) {
                        window.addEventListener(eventType, function(e) {
                            window.executionLog.events.push({
                                type: eventType,
                                target: e.target ? e.target.nodeName : 'unknown',
                                timestamp: Date.now()
                            });
                        }, true);
                    });
                } catch(e) {
                    console.error('Event monitoring setup failed:', e);
                }

                // Safe mutation monitoring
                try {
                    new MutationObserver(function(mutations) {
                        mutations.forEach(function(mutation) {
                            try {
                                window.executionLog.mutations.push({
                                    type: mutation.type,
                                    target: mutation.target ? mutation.target.nodeName : 'unknown',
                                    addedNodes: Array.from(mutation.addedNodes).map(function(n) {
                                        try {
                                            return {
                                                type: n.nodeName,
                                                html: n.outerHTML || n.textContent,
                                                attributes: n.attributes ? 
                                                    Array.from(n.attributes).map(function(a) {
                                                        return {
                                                            name: a.name,
                                                            value: a.value
                                                        };
                                                    }) : []
                                            };
                                        } catch(e) {
                                            return {error: e.message};
                                        }
                                    }),
                                    timestamp: Date.now()
                                });
                            } catch(e) {
                                console.error('Mutation processing error:', e);
                            }
                        });
                    }).observe(document, {
                        childList: true,
                        subtree: true,
                        attributes: true,
                        characterData: true
                    });
                } catch(e) {
                    console.error('Mutation observer setup failed:', e);
                }

                // Safe network monitoring
                try {
                    if (window.fetch) {
                        let originalFetch = window.fetch;
                        window.fetch = function() {
                            try {
                                window.executionLog.network.push({
                                    type: 'fetch',
                                    url: arguments[0],
                                    timestamp: Date.now()
                                });
                            } catch(e) {}
                            return originalFetch.apply(this, arguments);
                        };
                    }

                    if (window.XMLHttpRequest) {
                        let originalOpen = window.XMLHttpRequest.prototype.open;
                        window.XMLHttpRequest.prototype.open = function() {
                            try {
                                window.executionLog.network.push({
                                    type: 'xhr',
                                    method: arguments[0],
                                    url: arguments[1],
                                    timestamp: Date.now()
                                });
                            } catch(e) {}
                            return originalOpen.apply(this, arguments);
                        };
                    }
                } catch(e) {
                    console.error('Network monitoring setup failed:', e);
                }

                // Initial state capture
                window.executionLog.states.push(window.executionLog.captureState());
            } catch(e) {
                console.error('Monitor script initialization failed:', e);
            }
            """

            # Function to safely collect execution data
            collect_execution_data = """
            try {
                return {
                    executionLog: window.executionLog || {error: 'Execution log not available'},
                    finalState: (function() {
                        try {
                            return window.executionLog.captureState();
                        } catch(e) {
                            return {error: e.message};
                        }
                    })(),
                    documentContent: (function() {
                        try {
                            return document.documentElement.outerHTML;
                        } catch(e) {
                            return 'Error capturing document content: ' + e.message;
                        }
                    })(),
                    currentUrl: window.location.href,
                    performance: (function() {
                        try {
                            return {
                                timing: performance.timing,
                                navigation: performance.navigation,
                                entries: performance.getEntries().map(function(e) {
                                    return {
                                        name: e.name,
                                        type: e.entryType,
                                        duration: e.duration
                                    };
                                })
                            };
                        } catch(e) {
                            return {error: e.message};
                        }
                    })()
                };
            } catch(e) {
                return {error: 'Data collection failed: ' + e.message};
            }
            """

            if method == 'GET':
                try:
                    logging.debug("=== Starting GET Request Processing ===")
                    logging.debug(f"actions: {actions}")
                    if payload:
                        # Get endpoint from actions and ensure it's a string
                        endpoint = actions.get('endpoint', '')
                        if isinstance(endpoint, dict):
                            logging.debug("Endpoint is dict: %s" % str(endpoint))
                            endpoint = endpoint.get('url', '')  # Extract URL from dict if needed
                        endpoint = str(endpoint).strip()
                        parsed_url = urlparse(endpoint)
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}".rstrip('/')
                        
                        # Handle payload based on type
                        payload = actions.get('payload', {})
                        parameter = actions.get('parameter', '').strip()
                        
                        # Build query parameters
                        if isinstance(payload, dict):
                            # Use dictionary payload directly
                            params = payload
                        elif payload:
                            # Convert string payload to dictionary with parameter
                            params = {parameter: str(payload)}
                        else:
                            params = {}
                            
                        # Build final URL with query parameters    
                        if params:
                            query_string = urlencode(params, quote_via=quote_plus, safe='')
                            url = f"{base_url}?{query_string}"
                        else:
                            url = base_url
                            
                        logging.info(f"Sending GET request to: {url}")
                        logging.debug(f"Using payload: {payload} for parameter: {parameter}")
                        
                        self.browser.execute_script(monitor_script)
                        self.browser.get(url)
                        
                        try:
                            WebDriverWait(self.browser, 10).until(
                                lambda driver: driver.execute_script('return document.readyState') == 'complete'
                            )
                            execution_data = self.browser.execute_script(collect_execution_data)
                            
                            response_data = {
                                'status_code': 200,
                                'body': execution_data['documentContent'],
                                'url': execution_data['currentUrl'],
                                'execution_log': execution_data['executionLog']
                            }
                            return self.handle_new_response(response_data, actions)
                            
                        except Exception as e:
                            if "unexpected alert" in str(e):  # Only handle alert if that's what caused the error
                                try:
                                    alert = self.browser.switch_to.alert
                                    alert_text = alert.text
                                    alert.accept()
                                    
                                    response_data = {
                                        'status_code': 200,
                                        'body': 'Alert triggered: ' + alert_text,
                                        'url': self.browser.current_url,
                                        'execution_log': {'alert_triggered': True, 'alert_text': alert_text}
                                    }
                                    return self.handle_new_response(response_data, actions)
                                except:
                                    pass  # If alert handling fails, raise the original error
                            raise  # Re-raise the original error if it wasn't an alert

                except Exception as e:
                    logging.error(f"Error during GET request: {str(e)}")
                    return []

            elif method == 'POST':
                logging.debug(f"=== Starting POST Request Processing ===")
                logging.debug(f"Endpoint: {endpoint}")
                logging.debug(f"Full payload dictionary: {payload}")
                logging.debug(f"Actions: {actions}")
                
                try:
                    # Validate payload
                    if not isinstance(payload, dict):
                        logging.error(f"Invalid payload type: {type(payload)}")
                        return []
                    if not payload:
                        logging.error("Empty payload dictionary")
                        return []
                    logging.debug(f"Payload validation passed. Keys: {list(payload.keys())}")

                    # Navigate to page first
                    logging.debug(f"Navigating to: {endpoint}")
                    self.browser.get(endpoint)
                    logging.debug("Navigation successful")
                    
                    # Wait for page load and inject monitoring script
                    wait = WebDriverWait(self.browser, 10)
                    logging.debug("Waiting for initial page load...")
                    wait.until(lambda driver: driver.execute_script('return document.readyState') == 'complete')
                    logging.debug("Page load complete")
                    
                    logging.debug("Injecting monitoring script...")
                    self.browser.execute_script(monitor_script)
                    logging.debug("Monitoring script injected successfully")

                    # Modified fill script with logging
                    fill_script = """
                        try {
                            const payload = arguments[0];
                            console.log('Received payload:', payload);
                            
                            for (let [name, value] of Object.entries(payload)) {
                                console.log(`Looking for field: ${name}`);
                                const field = document.querySelector(`[name="${name}"]`);
                                if (field) {
                                    console.log(`Found field ${name}, setting value: ${value}`);
                                    field.value = value;
                                    field.dispatchEvent(new Event('change'));
                                } else {
                                    console.log(`Field not found: ${name}`);
                                }
                            }
                            
                            console.log('Looking for form...');
                            const form = document.querySelector('form');
                            if (form) {
                                console.log('Form found, submitting...');
                                form.submit();
                                return {success: true, message: 'Form submitted'};
                            } else {
                                console.log('No form found!');
                                return {success: false, message: 'No form found'};
                            }
                        } catch (error) {
                            console.error('Error in fill script:', error);
                            return {success: false, error: error.toString()};
                        }
                    """
                    
                    logging.debug("Executing fill script...")
                    result = self.browser.execute_script(fill_script, payload)
                    logging.debug(f"Fill script result: {result}")

                    logging.debug("Waiting for form submission to complete...")
                    wait.until(lambda driver: driver.execute_script('return document.readyState') == 'complete')
                    logging.debug("Form submission complete")

                    logging.debug("Collecting execution data...")
                    execution_data = self.browser.execute_script(collect_execution_data)
                    logging.debug("Execution data collected")
                    
                    response_data = {
                        'status_code': 200,
                        'body': execution_data['documentContent'],
                        'url': self.browser.current_url,
                        'execution_log': execution_data['executionLog']
                    }
                    logging.debug(f"Final URL: {self.browser.current_url}")
                    
                    return self.handle_new_response(response_data, actions)
                    
                except Exception as e:
                    if "unexpected alert" in str(e):
                        try:
                            logging.debug("Handling alert...")
                            alert = self.browser.switch_to.alert
                            alert_text = alert.text
                            logging.debug(f"Alert text: {alert_text}")
                            alert.accept()
                            
                            response_data = {
                                'status_code': 200,
                                'body': f'Alert triggered: {alert_text}',
                                'url': self.browser.current_url,
                                'execution_log': {'alert_triggered': True, 'alert_text': alert_text}
                            }
                            return self.handle_new_response(response_data, actions)
                        except:
                            logging.error("Failed to handle alert", exc_info=True)
                    logging.error(f"Error during POST request: {str(e)}", exc_info=True)
                    return []
        except Exception as e:
            logging.error("Error during request processing", exc_info=True)
            return []

    def extract_form_actions(self, response_str):
        logging.debug("Extracting form actions using InputFieldParser...")
        form_actions = []
        try:
            parser = FormParser()
            try:
                # Basic sanitization of response string
                clean_response = response_str.strip()
                if clean_response:
                    parser.feed(clean_response)
                    forms = parser.get_forms()
                else:
                    forms = []
            except Exception:
                logging.debug("HTML parsing error encountered - skipping malformed HTML")
                forms = []
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET')
                form_inputs = form.get('inputs', [])
                form_data = {
                    "action": form_action,
                    "method": form_method,
                    "inputs": form_inputs
                }
                form_actions.append('FORM::' + simplejson.dumps(form_data))
                logging.debug("Extracted form with action: " + form_action + ", method: " + form_method)
        except Exception as e:
            self.log_exception("Exception in extract_form_actions", e)
        return form_actions
    

    def log_exception(self, message, e):
        error_message = message + ": " + str(e)
        logging.error(error_message)
        logging.error("Traceback:\n" + traceback.format_exc())

    def log_uncaught_exceptions(self, exctype, value, tb):
        logging.error("Uncaught exception:", exc_info=(exctype, value, tb))

    def autonomous_testing_cycle(self):
        try:
            logging.debug("Starting autonomous_testing_cycle with max_iterations=%d", self.max_iterations)
            while self.autonomous_enabled and self.iteration < self.max_iterations:
                # Calculate remaining iterations
                remaining = self.max_iterations - self.iteration
                tasks_to_submit = min(40, remaining)  # Submit up to 40 tasks or the remaining number

                logging.debug("Submitting %d tasks. Current iteration: %d", tasks_to_submit, self.iteration)
                for _ in range(tasks_to_submit):
                    if not self.autonomous_enabled or self.iteration >= self.max_iterations:
                        break
                    # Create a Callable task
                    task = CallableTask(self.process_random_subdirectory)
                    # Submit the task
                    future = self.executor.submit(task)
                    self.futures.append(future)
                    self.iteration += 1
                    logging.debug("Submitted task. Current iteration: %d/%d", self.iteration, self.max_iterations)
                
                # Optional: Short sleep to prevent tight loop
                time.sleep(0.5)
            
            # Wait for all submitted tasks to complete
            for future in self.futures:
                try:
                    result = future.result()  # Blocks until the task is complete
                    if not result:
                        logging.warning("A task completed with failure.")
                except Exception as e:
                    self.log_exception("Exception in thread pool task", e)
            
            if self.iteration >= self.max_iterations:
                self.update_text_area("Completed maximum iterations (%d)\n" % self.max_iterations)
                logging.info("Autonomous testing completed at %d iterations.", self.max_iterations)
                self.write_report()
            
            self.autonomous_enabled = False
            self.update_status()
        
        except Exception as e:
            self.log_exception("Error in autonomous testing cycle", e)
            self.autonomous_enabled = False
            self.update_status()
        finally:
            # Clear the futures list
            self.futures = []
            logging.debug("Ending autonomous_testing_cycle. Total iterations: %d", self.iteration)

    def write_report(self):
        try:
            f = open("vulnerabilities.json", "w")
            json_str = '[' + ','.join(simplejson.dumps(vuln) for vuln in self.vulnerabilities_to_write) + ']'
            f.write(json_str)
        except Exception as e:
            logging.error("Failed to write vulnerability to file: %s", str(e))
        finally:
            f.close()
        # Path to the Selenium parser script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        ioc_script = os.path.join(script_dir, "vulnReport.py")
        if not os.path.exists(ioc_script):
            self.update_text_area("Report script not found: %s\n" % ioc_script)
            logging.error("Report script not found: %s" % ioc_script)
            return
        try:             
            logging.debug("Triggering Report identifier script...")
            # Command to execute the parser script
            command = "python %s" % (ioc_script)
            logging.debug("Executing command: %s" % command)
            # self.update_text_area("Launching IOC parsing script...\n")
            

            # Start the subprocess
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
        except Exception as e:
            self.log_exception("Error executing report", e)
            return


    def process_random_subdirectory(self):
        try:
            logging.debug("Starting endpoint processing...")
            # Load sitemap data
            try:
                if not os.path.exists(self.json_file_path):
                    logging.warning("Sitemap has not been parsed yet.")
                    self.update_text_area("Please parse sitemap first.\n")
                    return False
                try:
                    with open(self.json_file_path, 'r') as f:
                        self.parsed_data = simplejson.load(f)
                except Exception as e:
                    logging.error("Error loading sitemap data: %s", str(e))
                    self.update_text_area("Error loading sitemap data. Please parse sitemap again.\n")
                    return False
                
            except Exception as e:
                logging.error("Unexpected error during sitemap loading: %s", str(e))
                self.update_text_area("Unexpected error during sitemap loading.\n")
                return False

            # Get domains data
            domains_data = self.parsed_data.get("domains", {})
            if not domains_data:
                logging.warning("No domains found in parsed data")
                self.update_text_area("No domains found in parsed data.\n")
                return False

            # Collect endpoints with defined parameters or forms
            valid_endpoints = []
            for domain, domain_data in domains_data.items():
                endpoints = domain_data.get("endpoints", {})
                if not endpoints:
                    logging.debug("No endpoints found for domain: %s" % domain)
                    continue

                for path, endpoint_data in endpoints.items():
                    # Extract GET and POST parameters
                    get_params = endpoint_data.get("GET", {}).get("parameters", [])
                    post_params = endpoint_data.get("POST", {}).get("parameters", [])
                    forms = endpoint_data.get("POST", {}).get("forms", [])

                    has_get_params = bool(get_params)
                    has_post_params = bool(post_params)
                    has_forms = bool(forms)

                    # Check if any parameter is a filter parameter
                    filter_get_params = set(param.lower() for param in get_params)
                    filter_post_params = set(param.lower() for param in post_params)

                    is_filter_endpoint = bool(filter_get_params or filter_post_params)

                    # Log filter details
                    if is_filter_endpoint:
                        logging.debug(
                            "Endpoint %s%s has filter parameters: GET=%s, POST=%s",
                            domain, path,
                            list(filter_get_params),
                            list(filter_post_params)
                        )

                    # Determine the HTTP method priority
                    # If forms exist, prefer POST; else, prefer GET if parameters exist
                    if has_post_params or has_forms:
                        method = "POST"
                    elif has_get_params:
                        method = "GET"
                    else:
                        method = "UNKNOWN"

                    # Only consider endpoints with parameters or forms
                    if has_get_params or has_post_params or has_forms:
                        endpoint = {
                            "url": "https://%s%s" % (domain, path),
                            "method": method, 
                            "data": endpoint_data,
                            "parameter_types": {
                                "GET": has_get_params,
                                "POST": has_post_params,
                                "forms": has_forms
                            },
                            "filter_parameters": {
                                "GET": list(filter_get_params),
                                "POST": list(filter_post_params) 
                            }
                        }
                        valid_endpoints.append(endpoint)
                        logging.debug(
                            "Found valid endpoint: %s with method: %s, filter_parameters: %s",
                            endpoint["url"],
                            endpoint["method"],
                            endpoint["filter_parameters"]
                        )

            if not valid_endpoints:
                logging.warning("No endpoints with parameters/forms found")
                self.update_text_area("No endpoints with parameters/forms found.\n")
                return False

            # Select and process random endpoint
            selected_endpoint = random.choice(valid_endpoints)
            url = selected_endpoint["url"]
            param_types = selected_endpoint["parameter_types"]
            
            logging.info("Selected endpoint for testing: %s" % url)
            self.update_text_area("Testing endpoint: %s\n" % url)

            # Analyze endpoint for injection opportunities
            analysis_data = self.analyze_endpoint_for_injection(selected_endpoint)
            if not analysis_data:
                logging.error("Failed to analyze endpoint")
                self.update_text_area("Failed to analyze endpoint. Check logs for details.\n")
                return False

            # Generate payload based on analysis
            payload = self.create_payload(analysis_data)
            if not payload:
                logging.error("Failed to create payload")
                self.update_text_area("Failed to create payload. Check logs for details.\n")
                return False

            # Send to OpenAI for payload generation
            openai_response = self.send_request_to_openai(payload)
            if not openai_response:
                logging.error("No response from OpenAI")
                self.update_text_area("No response from OpenAI. Check logs for details.\n")
                return False

            # Parse OpenAI response
            payload_parsed = self.parse_openai_response(openai_response)
            if not payload_parsed:
                logging.error("Failed to parse OpenAI response")
                self.update_text_area("Failed to parse OpenAI response. Check logs for details.\n")
                return False

            # Process the payload
            if isinstance(payload_parsed, str):
                json_match = re.search(r'```json\s*(\{.*?\})\s*```', payload_parsed, re.DOTALL)
                if json_match:
                    try:
                        payload_json = simplejson.loads(json_match.group(1).strip())
                        logging.debug(f"Parsed payload JSON: {payload_json}")
                        
                        # Send the entire payload dictionary
                        temp_data = dict(analysis_data)
                        temp_data['payload'] = payload_json  # Pass the complete dictionary
                        temp_data['endpoint'] = selected_endpoint["url"]
                        temp_data['method'] = selected_endpoint["method"]
                        
                        logging.debug(f"Prepared request data: {temp_data}")
                        
                        parsed_url = urlparse(selected_endpoint["url"])
                        http_service = self.create_http_service(parsed_url)
                        
                        self.generate_and_send_requests(http_service, temp_data)
                            
                    except Exception as e:
                        logging.error("Error processing payload JSON: %s", str(e))
                        self.update_text_area("Error processing payload. Check logs for details.\n")
                        return False
                else:
                    logging.warning("No JSON payload found in OpenAI response")
                    self.update_text_area("No valid payload found in response.\n")
            else:
                logging.warning("Unexpected payload format: %s" % type(payload_parsed))
                self.update_text_area("Unexpected payload format received.\n")

            return True
            
        except Exception as e:
            self.log_exception("Error in process_random_subdirectory", e)
            self.update_text_area("Error processing endpoint. Check logs for details.\n")
            return False

    def handle_new_response(self, response, actions=None):
        """Handle response from requests, without Burp dependencies"""
        try:
            if response and response.get('body'):
                # Get request info from response object including URL and payload
                # Extract request information from the actions dictionary
                method = actions.get('method', 'GET')
                url = response.get('url', '')
                request_str = f"{method} {url}"
                response_str = response.get('body', '')
                
                # Get request details
                method = response.get('request', {}).get('method')
                url = response.get('request', {}).get('url')

                if actions is None:
                    actions = {}
                actions['request'] = request_str
                
                # Get LLM analysis
                insights = self.analyze_with_openai(response, request_str, response_str, actions)
                    
                # Extract suggested actions from insights
                suggested_actions = self.extract_suggestions(insights)
                
                # Extract form actions from response HTML
                form_actions = self.extract_form_actions(response_str)
                
                return suggested_actions + form_actions
                    
            else:
                logging.warning("No response content to handle in handle_new_response.")
                return []
                
        except Exception as e:
            logging.error("Error in handle_new_response: %s" % str(e))
            logging.error(traceback.format_exc())
            return []


    def shutdown_executor(self):
        try:
            self.executor.shutdown()
            self.executor.awaitTermination(60, TimeUnit.SECONDS)  # Wait up to 60 seconds for tasks to finish
            logging.info("ExecutorService has been shut down gracefully.")
        except Exception as e:
            logging.error("Error shutting down ExecutorService: %s", str(e))
            

    def update_autonomous_table(self, raw_request, endpoint, action, summary, status):
        """Update the autonomous table with formatted results"""
        try:
            # Insert new row into tkinter treeview table
            self.results_table.insert(
                '', 'end',  # Parent = '', Position = end
                values=(
                    raw_request,
                    endpoint,
                    action,  # Method + Payload 
                    summary, # Raw request + Analysis
                    status   # Vulnerability confidence
                )
            )
                
            # Update the table display
            self.results_table.update()

        except Exception as e:
            self.log_exception("Exception occurred while updating autonomous table", e)

    def analyze_response(self, domain, path, response):
        try:
            # Extract headers and body from response object
            headers = dict(response.headers)
            body = response.text
            
            # Check content type
            content_type = headers.get('content-type', '').lower()
            logging.debug("Content-Type for %s: %s" % (path, content_type))
            
            if not content_type or 'text/html' not in content_type:
                logging.debug("Skipping non-HTML response for %s" % path) 
                return
            
            logging.debug("Parsing HTML body of length %d for %s" % (len(body), path))
            # Find forms using FormParser
            form_parser = FormParser()
            form_parser.feed(body)
            forms = form_parser.get_forms()

            # Skip if no forms found
            if not forms:
                logging.debug("No forms found in %s" % path)
                return

            logging.info("Found %d forms in %s" % (len(forms), path))
            
            # For each form found
            for form in forms:
                # Extract input fields and get names for each
                inputs = []
                inputs_section = form.get('inputs', [])
                
                # Process each input field
                for input_field in inputs_section:
                    name = input_field.get('name', '')
                    if not name:
                        # Try to get name from attributes like id, placeholder etc
                        field_type = input_field.get('type', 'text')
                        if field_type in ['text', 'hidden', 'password', 'email']:
                            # Look for input identifiers in body near this input
                            input_text = input_field.get('value', '')
                            if input_text:
                                name = input_text
                            else:
                                # Default to type if no other identifiers found
                                name = field_type
                    
                    # Add processed input to form
                    input_field['name'] = name
                    inputs.append(input_field)
                
                # Update form with processed inputs
                form['inputs'] = inputs
                
                # Add form to results
                if form not in self.results["domains"][domain]["endpoints"][path]["POST"]["forms"]:
                    self.results["domains"][domain]["endpoints"][path]["POST"]["forms"].append(form)
                    logging.debug("Form details: %s" % form)

        except Exception as e:
            logging.error("Error analyzing response: %s" % str(e))

            
    def analyze_request(self, domain, path, request):
        # Analyze request object from Python requests library
        try:
            # Get method from request
            method = request.method
            
            # Mark HTTP method as available
            if method in ["GET", "POST"]:
                self.results["domains"][domain]["endpoints"][path][method]["available"] = True

            # Get parameters from request
            params = {}
            
            # Handle GET parameters from URL
            if request.url and '?' in request.url:
                query = urlparse(request.url).query
            url_params = parse_qs(query)
            for param_name in url_params.keys():
                if param_name not in self.results["domains"][domain]["endpoints"][path]["GET"]["parameters"]:
                    self.results["domains"][domain]["endpoints"][path]["GET"]["parameters"].append(param_name)
                
            # Handle POST parameters from body
            if method == "POST":
                # Handle form data
                if request.body:
                    try:
                        # Try to parse as form data
                        if isinstance(request.body, str):
                            body_params = parse_qs(request.body)
                        else:
                            body_params = request.body
                            
                        for param_name in body_params.keys():
                            if param_name not in self.results["domains"][domain]["endpoints"][path]["POST"]["parameters"]:
                                self.results["domains"][domain]["endpoints"][path]["POST"]["parameters"].append(param_name)
                    except:
                    # Try to parse as JSON
                        try:
                            json_params = simplejson.loads(request.body)
                            if isinstance(json_params, dict):
                                for param_name in json_params.keys():
                                    if param_name not in self.results["domains"][domain]["endpoints"][path]["POST"]["parameters"]:
                                        self.results["domains"][domain]["endpoints"][path]["POST"]["parameters"].append(param_name)
                        except:
                            logging.warning(f"Could not parse POST body for {path}")
                    
        except Exception as e:
            logging.error(f"Error analyzing request: {str(e)}")

    def save_api_key(self):
        """Save the API key to config file and update the instance variable"""
        api_key = self.api_key_var.get().strip()
        if api_key:
            self.api_key = api_key
            try:
                with open("config.txt", "w") as f:
                    f.write(f"OPENAI_API_KEY={api_key}")
                messagebox.showinfo("Success", "API key saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save API key: {str(e)}")
        else:
            messagebox.showwarning("Warning", "Please enter an API key.")

def main():
    # Set up logging configuration
    logging.basicConfig(
        filename="scanner.log",
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s:%(message)s",
    )
    
    # Clear the failed_payloads.json file if it exists
    if os.path.exists("failed_payloads.json"):
        os.remove("failed_payloads.json")
        logging.info("Removed existing failed_payloads.json file")
    
    # Initialize and start your web scanner
    scanner = WebScanner()
    scanner.run()

# Ensure this block is at the bottom of your script
if __name__ == "__main__":
    main()