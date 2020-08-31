#!/usr/bin/env python3
import os
import time
import string
import random
import urllib3
import requests
import argparse
from multiprocessing import Pool

# Add arguments
parser = argparse.ArgumentParser(description="A Python script to request multiple URLs from a file and store each response in a different file")
parser.add_argument("-v", "--verbose", type=str, help="Print current HTTP request and response status code")
parser.add_argument("-H", "--header", type=str, help="HTTP headers to send in the request (key: value) - Multiple uses are allowed", action="append")
parser.add_argument("-t", "--threads", type=int, help="Threads (Default 10)", default=10)
parser.add_argument("--timeout", type=int, help="This tells the program how long to wait for a response from the server", default=1)
parser.add_argument("-n", "--nmap", type=str, help="Nmap XML scan file", metavar="FILE")
parser.add_argument("-o", "--out", type=str, help="Directory to store output in")
parser.add_argument("-f", "--file", type=str, help="File containing URLs to fetch")

# Parse command line
args         = parser.parse_args()
nmap         = args.nmap
timeout      = args.timeout
in_file      = args.file
output_dir   = args.out
verbosity    = args.verbose
user_header  = args.header
thread_count = args.threads

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.connection.HTTPConnection)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.connection.VerifiedHTTPSConnection)

# HTTP headers
headers = {}

"""
Headers -H
"""
if user_header:
	for h in user_header:
		http_header = h.split(":")
		header_key  = http_header[0].strip()
		header_val  = http_header[1].strip()
		headers[header_key] = header_val

"""
Random character generator for file name
"""
def rand_char_gen(file_name_length=35):
	characters = string.ascii_letters + string.digits
	return ''.join(random.choice(characters) for i in range(file_name_length))

"""
Open and write to output file
"""
def write_to_output_file(file_name, url, response_size, status, data):
	with open(output_dir + "/" + file_name + "-" + response_size + "-" + status + ".html", "w") as f:
		f.write("# URL: " + url + "\n")
		f.write("# FILE: " + file_name + "\n")
		f.write("# STATUS: " + status + "\n")
		f.write("# \n\n")
		f.write(data)

"""
GET URLs Nmap
"""
def get_urls_nmap(url):
	try:
		r = requests.get(url, timeout=timeout, headers=headers, verify=False)
		if args.verbose:
			print("[+] Trying: %d\t%d\thttp://%s/" % (r.status_code, len(r.text), url,))
		file_name = rand_char_gen()
		write_to_output_file(file_name, url, str(len(r.text)), str(r.status_code), r.text)

	# Handle exceptions
	except requests.exceptions.Timeout:
		pass
	except requests.exceptions.ConnectionError:
		pass
	except Exception as e:
		print(e)

"""
GET URLs basic
"""
def get_urls_basic(url):
	try:
		r1 = requests.get("http://" + url + "/", timeout=timeout, headers=headers, verify=False)
		r2 = requests.get("https://" + url + "/", timeout=timeout, headers=headers, verify=False)

	    # Check if verbose flag is set
		if args.verbose:
			print("[+] Trying:\t%s\t%d\t%d" % (url, len(r.text), r.status_code))

		if r1:
			print("[+] %d\t%d\thttp://%s/" % (r1.status_code, len(r1.text), url,))
			file_name_1 = rand_char_gen()
			write_to_output_file(file_name_1, url, str(len(r1.text)), str(r1.status_code), r1.text)
		else:
			if r1.status_code == 301 or r1.status_code == 302 or r1.status_code == 404:
				print("[+] %d\t%d\thttp://%s/" % (r1.status_code, len(r1.text), url,))
			file_name_1 = rand_char_gen()
			write_to_output_file(file_name_1, url, str(len(r1.text)), str(r1.status_code), r1.text)

		if r2:
			print("[+] %d\t%d\thttp://%s/" % (r2.status_code, len(r2.text), url,))
			file_name_2 = rand_char_gen()
			write_to_output_file(file_name_2, url, str(len(r2.text)), str(r2.status_code), r2.text)
		else:
			if r2.status_code == 301 or r2.status_code == 302 or r2.status_code == 404:
				print("[+] %d\t%d\thttp://%s/" % (r2.status_code, len(r2.text), url,))
			file_name_2 = rand_char_gen()
			write_to_output_file(file_name_2, url, str(len(r2.text)), str(r2.status_code), r2.text)

	# Handle exceptions
	except requests.exceptions.Timeout:
		pass
	except requests.exceptions.ConnectionError:
		pass
	except Exception as e:
		print(e)

"""
Main
"""
def main():
	if args.out:
		try:
			print("[+] Creating output directory: %s" % output_dir)
			os.mkdir(output_dir)
		except:
			print("[+] Output directory exists: %s" % output_dir)

	print(r"""
 _____ _____ _____  _     ____  _     ____ 
/  __//  __//__ __\/ \ /\/  __\/ \   / ___\
| |  _|  \    / \  | | |||  \/|| |   |    \
| |_//|  /_   | |  | \_/||    /| |_/\\___ |
\____\\____\  \_/  \____/\_/\_\\____/\____/
                                           
""")
	print(f"[+] Threads: {thread_count}")
	print(f"[+] Headers: {user_header}")
	print(f"[+] Timeout: {timeout}")
	print("----------------------------------------------------------------------")
	print("    Status Code    |    Response Size    |    Target URL")
	print("----------------------------------------------------------------------")

	if args.nmap:
		url = []
		in_file_nmap = args.nmap
		tree 		 = ET.parse(in_file)
		root 		 = tree.getroot()
		for x in root:
			for y in x:
				for z in y:
					if z.tag == "hostname":
						host = z.attrib["name"]
					if z.tag == "port":
						port = z.attrib["portid"]
						if port == "80":
							url.append("http://" + host + ":" + port + "/").strip()
						elif port == "443":
							url.append("https://" + host + ":" + port + "/").strip()
						else:
							url.append("http://" + host + ":" + port + "/").strip()
		try:
			with Pool(thread_count) as pool:
				results = pool.map(get_urls_nmap, url)
				success = list(filter(None, results))
		except KeyboardInterrupt:
			print("[+] Exiting program...")
			time.sleep(3)


	elif args.file:
		try:
			with open(in_file, "r") as url_file:
				urls = url_file.readlines()
				url  = [i.strip() for i in urls]
				print(f"[DEBUG] {type(url)}")
			with Pool(thread_count) as pool:
				results = pool.map(get_urls_basic, url)
				success = list(filter(None, results))
		except KeyboardInterrupt:
			print("[+] Exiting program...")
			time.sleep(3)

	else:
		print("[!] You must specify either -f or --nmap")
		return 1

	print("[+] DONE: Output saved in: %s" % output_dir)

	return 0

if __name__ == "__main__":
	main()
