# Use NMAP to check the server and the port to make sure that it is not filtered
import argparse
import subprocess
import shlex
import re
import datetime
import elasticsearch
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q
import threading
import time




def check_ip_port(ip, port, protocol, timeout):
	"""
	Check the port of the given IP to see whether it is open/filtered/closed
	"""
	# default is TCP port, we do not support UDP at this time yet 
	#print protocol
	nmap_command = "/usr/local/bin/nmap -T4  -host-timeout 3m -p {} -A -Pn {}".format(port, ip)
	pattern_filtered = re.compile("{}/tcp filtered".format(port))
	pattern_open = re.compile("{}/tcp open".format(port))
	pattern_closed = re.compile("{}/tcp closed".format(port))
	pattern_open_filtered = re.compile("{}/tcp open|filtered".format(port))
	pattern_timeout = re.compile("host timeout")
	if protocol == "UDP":
	    nmap_command = "sudo /usr/local/bin/nmap -T4 -host-timeout 3m -sU --version-intensity 0 -p {} -A -Pn {}".format(port, ip)
	    pattern_filtered = re.compile("{}/udp filtered".format(port))
	    pattern_open = re.compile("{}/udp open".format(port))
	    pattern_closed = re.compile("{}/udp closed".format(port))
	    pattern_open_filtered = re.compile("{}/udp open|filtered".format(port))
	if timeout == "yes":
	 	nmap_command = "sudo /usr/local/bin/nmap -T4 -host-timeout 3m -sU --version-intensity 0 -p {} -sV --version-intensity 0 -Pn {}".format(port, ip)
	#print nmap_command
	p = subprocess.Popen(shlex.split(nmap_command), stdout=subprocess.PIPE)

	return_code = "none"
	result = p.communicate()[0]
	
	
	if re.search(pattern_filtered, result):
		return_code = "filtered"
	elif re.search(pattern_open, result):
		return_code = "open"
	elif re.search(pattern_closed, result):
		return_code = "closed"
	elif re.search(pattern_open_filtered, result):
		return_code = "open_filtered"
	elif re.search(pattern_timeout, result):
		return_code = "timeout"
	#print result
	return (return_code, result)


def check_in_EL(ip_address, port, protocol, last_test_date):
	"""
	check whether the result is already in ELK
	"""
	index_name = "externalservices"
	try:
		client = Elasticsearch([{'host':'localhost','port':9200}])
		query = Q('match', ip_address=ip_address) & Q('match', port = int(port)) & Q('match',  protocol = protocol) & Q('match', last_test_date = last_test_date)
		s = Search(using=client, index=index_name).filter(query)
		response = s.execute()
		if (len(response) > 0):
			return "yes"
		else:
			return "no"
	except elasticsearch.ElasticsearchException as es1:
		print "error"
		return "no"

def update_service(line):
	"""
	Update the service status using the information provided
	"""
	(ip_address,host_name,os,os_version,port,protocol,service,service_name,service_version) = line.split(",")
	print line

	# check whether the result is already in the database for today
	# if yes, no need to check again 
	index_name = "externalservices"
	client = Elasticsearch([{'host':'localhost','port':9200}])
	today_date = datetime.datetime.now().strftime("%Y-%m-%d")
	
	in_EL = check_in_EL(ip_address, port, protocol, today_date)
	if (in_EL == "yes"):
		return 	
	
	# check ip port 
	timeout = "no"
	(code, nmap_result) = check_ip_port(ip_address,port, protocol, timeout)
	if code == "timeout":
		timeout = "yes"
		(code, nmap_result) = check_ip_port(ip_address,port, protocol, timeout)


	external_service = {
		"ip_address" : ip_address,
		"port" : int(port),
		"protocol" : protocol,
		"r7_os" : os,
		"r7_os_version" : os_version,
		"r7_service" : service,
		"r7_service_name" :  service_name,
		"r7_service_version" : service_version, 
		"nmap_state" : code,
		"last_test_date" :  today_date,
		"nmap_result" : nmap_result
		}
		
	res = client.index(index=index_name, doc_type='service', body=external_service)
	#print  res




parser = argparse.ArgumentParser(
	description='''Check the server and port using NMAP to remove filtered ports.
				''')

parser.add_argument('-f', '--file', help='csv file name')

args = parser.parse_args()

#open file and load the result
with open(args.file) as f:
	r7_data = f.readlines()

for data in r7_data:
	(ip_address,host_name,os,os_version,port,protocol,service,service_name,service_version) = data.split(",")
	if (ip_address == "ip_address"):
		continue
	today_date = datetime.datetime.now().strftime("%Y-%m-%d")
	
	in_EL = check_in_EL(ip_address, port, protocol, today_date)
	if (in_EL == "yes"):
		continue

	t1 = threading.Thread(target=update_service, args=(data,)) 
	t1.start()
	time.sleep(2)
	
