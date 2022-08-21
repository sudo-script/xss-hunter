import requests
import re
import urlparse
from BeautifulSoup import BeautifulSoup
 
 
class Scanner:
    def __init__(self, url, ignore_links):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []
        self.links_to_ignore = ignore_links
 
    def extract_links_from(self, url):
        response = self.session.get(url)
        return re.findall('(?:href=")(.*?)"', response.content)
 
    def crawl(self, url=None):
        if url == None:
            url = self.target_url
        href_links = self.extract_links_from(url)
        for link in href_links:
            link = urlparse.urljoin(url, link)
 
            if "#" in link:
                link = link.split("#")[0]
 
            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                self.target_links.append(link)
                print(link)
                self.crawl(link)
 
    def extract_forms(self, url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content)
        return parsed_html.findAll("form")
 
    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urlparse.urljoin(url, action)
        method = form.get("method")
 
        inputs_list = form.findAll("input")
        post_data = {}
        for input in inputs_list:
            input_name = input.get("name")
            print(input_name)
            input_type = input.get("type")
            print(input_type)
            input_value = input.get("value")
            print(input_value)
            if input_type == "text":
                input_value = value
 
            post_data[input_name] = input_value
        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)
 
    def run_scanner(self):
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                print("[+] Testing form in " + link)
                is_vulnerable_to_xss = self.test_xss_in_form(form, link)
                if is_vulnerable_to_xss:
                    print("\n\n[***] XSS discovered in " + link + " in the follwing form")
                    print(form)
 
            if "=" in link:
                print("\n\n[+] Testing " + link)
                is_vulnerable_to_xss = self.test_xss_in_link(link)
                if is_vulnerable_to_xss:
                    print("[***] Discovered XSS in " + link)
 
    def test_xss_in_link(self, url):
        xss_test_script = "<sCript>alert('test')</scriPt>"
        url = url.replace("=", "=" + xss_test_script)
        response = self.session.get(url)
        return xss_test_script in response.content
 
    def test_xss_in_form(self, form, url):
        xss_test_script = "<sCript>alert('test')</scriPt>"
        response = self.submit_form(form, xss_test_script, url)
        return xss_test_script in response.content


Vulnerability Scanner:

#!/usr/bin/env python
 
import scanner
 
#target_url = "http://10.0.2.14/mutillidae/"
target_url = "http://10.0.2.14/dvwa/"
links_to_ignore = ["http://10.0.2.14/dvwa/logout.php"]
 
#data_dict = {"username": "blabla", "password": "123", "Login": "submit"}
data_dict = {"username": "admin", "password": "password", "Login": "submit"}
 
#response = requests.post(target_url, data = data_dict)
 
vuln_scanner = scanner.Scanner(target_url, links_to_ignore)
#vuln_scanner.session.post("http://10.0.2.14/dvwa/login.php", data=data_dict)
 
 
#forms = vuln_scanner.extract_forms("http://10.0.2.14/dvwa/vulnerabilities/xss_r/")
#print(forms)
 
#response = vuln_scanner.submit_form(forms[0], "test", "http://10.0.2.14/dvwa/vulnerabilities/xss_r/")
#response = vuln_scanner.test_xss_in_form(forms[0], "http://10.0.2.14/dvwa/vulnerabilities/xss_r/")
#response = vuln_scanner.test_xss_in_link("http://10.0.2.14/dvwa/vulnerabilities/xss_r/?name=ali")
#print(response)
#print(response.content)
vuln_scanner.crawl()
vuln_scanner.run_scanner()