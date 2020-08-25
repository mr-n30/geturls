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
parser.add_argument("-v", "--verbose", type=str, help="Print current HTTP request and response status code", metavar='')
parser.add_argument("-o", "--out", type=str, help="Directory to store output in", required=True, metavar='')
parser.add_argument("-H", "--header", type=str, help="HTTP headers to send in the request (key: value) - Multiple uses are allowed", action="append", metavar='')
parser.add_argument("-t", "--threads", type=int, help="Threads (Default 10)", metavar='', default=10)
parser.add_argument("-f", "--file", type=str, help="File containing URLs to fetch", required=True, metavar='')

# Parse command line
args         = parser.parse_args()
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
		f.write("# STATUS: " + status + "\n# \n")
		f.write(data)

"""
GET URLs
"""
def get_url(url):
	try:
		r1 = requests.get("http://" + url, timeout=0.500, headers=headers, verify=False)
		r2 = requests.get("https://" + url, timeout=0.500, headers=headers, verify=False)
		if args.verbose:
				print("[+] Trying:\t%s\t%d\t%d" % (url, len(r.text), r.status_code))
		if r1.status_code == 200 or r1.status_code == 301 or r1.status_code == 302:
				print("[+] %s\t%d\t%d" % (url, len(r1.text), r1.status_code))
		if r2.status_code == 200 or r2.status_code == 301 or r2.status_code == 302:
				print("[+] %s\t%d\t%d" % (url, len(r2.text), r2.status_code))
		file_name_1 = rand_char_gen()
		file_name_2 = rand_char_gen()
		write_to_output_file(file_name_1, url, str(len(r1.text)), str(r1.status_code), r1.text)
		write_to_output_file(file_name_2, url, str(len(r2.text)), str(r2.status_code), r2.text)
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
	try:
		print("[+] Creating output directory: %s" % output_dir)
		os.mkdir(output_dir)
	except:
		print("[+] Output directory exists: %s" % output_dir)

	print("[+] Threads: %s" % thread_count)
	print("[+] Headers: %s" % user_header)
	print("----------------------------------------------------------------------")
	print("\tTarget\t|\tResponse Size\t|\tStatus")
	print("----------------------------------------------------------------------")

	try:
		with open(in_file, "r") as url_file:
			urls = url_file.readlines()
			url = [i.strip() for i in urls]
		with Pool(thread_count) as pool:
			results = pool.map(get_url, url)
			success = list(filter(None, results))
	except KeyboardInterrupt:
		print("[+] Exiting program...")
		time.sleep(3)

	print("[+] DONE: Output saved in: %s" % output_dir)

if __name__ == "__main__":
	main()
