import dataset.data_reader as data_reader

import json
import sys
# import ipapi
from pandas.io.json import json_normalize
import hashlib
from termcolor import colored
import os
import virustotal
import sys

VT_API_KEY = "c6897aa50129b40c32139ed2ebe53214139eeb9068f87b43584e6016eb853932"
F_NAME = ""

def set_file(filename):
	global F_NAME
	F_NAME = filename

def get_file():
	global F_NAME
	return F_NAME	

def load_process_data():
	with open("./storage/"+get_file()+"/processes.json", 'r') as f:
		processes_dict = json.load(f)
	return processes_dict

def load_pe_imports_data():
	with open("./storage/"+get_file()+"/pe_imports.json", 'r') as f:
		processes_dict = json.load(f)
	return processes_dict

def load_info():
	with open("./storage/"+get_file()+"/executable_info.json", 'r') as f:
		info_dict = json.load(f)
	return info_dict

def load_string():
	with open("./storage/"+get_file()+"/string_debug.json", 'r') as f:
		info_dict = json.load(f)
	return info_dict


def virus_total_report(md5):
	v = virustotal.VirusTotal(VT_API_KEY)
	report = v.get(md5)
	print "Report"
	print "- Resource's UID:", report.id
	print "- Scan's UID:", report.scan_id
	print "- Permalink:", report.permalink
	print "- Resource's SHA1:", report.sha1
	print "- Resource's SHA256:", report.sha256
	print "- Resource's MD5:", report.md5
	print "- Resource's status:", report.status
	print "- Antivirus' total:", report.total
	print "- Antivirus's positives:", report.positives
	for antivirus, malware in report:
	    if malware is not None:
	        print
	        print "Antivirus:", antivirus[0]
	        print "Antivirus' version:", antivirus[1]
	        print "Antivirus' update:", antivirus[2]
	        print "Malware:", malware

def count_score(matches):
	temp = []
	score = []
	print "Analyzing Score"
	for match in matches:
		temp.append(match)
		score.append(match[1])
	if (temp):
		print "\nMenemukan "+str(len(temp))+" behavior\n"	
		print "Behavior :	"
		for tem in temp:
			print "	"+tem[0]
		print "Functions:" 
		for tem in temp:
			print tem[2]
		#check if there is some malicious behavior based on its score, 6 to 10 
		if ("10"or"9"or"8"or"7"or"6") in score:	
			print "\n======="+colored("Executable adalah malware", 'red')+"\n"
		else:
			print "\n======="+colored("Executable tidak malware", 'green')+"\n"

 
	else:
		print colored("=======Tidak ada behavior yang mencurigakan.",'green')+"\n\n"

def delete_duplicate(array):
	output = []
	for val in array:
		if not val in output:
			output.append(val)
	return output		
						
def analyze(malware_seq,application_api_seq):

	no_dup = delete_duplicate(application_api_seq)
	
	match_api = []
	matches = []
	temp = []
	
	for malware_csv_rows in malware_seq:
		# print malware_csv_rows
		for api in no_dup:	
			if api in malware_csv_rows:
				match_api.append(api)
		if match_api:
			temp = match_api
			matches.append([malware_csv_rows[0],malware_csv_rows[1],temp])
		match_api = []

	count_score(matches)


def main():
	dlls =[]
	application_api_seq = []
	
	malware_seq = data_reader.read_csv_malware_API()

	try :
		processes = load_process_data()		

		calls = processes['calls']

		for call in calls:
			application_api_seq.append(call['api'])
			
	except:
		print "tidak dapat menemukan behavior"		

	try :
		pe_imports = load_pe_imports_data()
		for pe_import in pe_imports:
			# print pe_import['dll']
			for imports in pe_import['imports']:
				# print imports['name']
				dlls.append(imports['name'])

	except:
		print "tidak dapat menemukan static"	 

	str=[]
	try :
		strings = load_string()
		for string in strings:
			str.append(string)

		# print dlls
	except:
		print "tidak dapat menemukan strings"		
				
	# print dlls


	sha1 = ""
	sha256 = ""
	sha512 = ""
	md5 = ""		

	infos = load_info()
	for info in infos:
		sha1 = infos['sha1']
		sha256 = infos['sha256']
		sha512 = infos['sha512']
		md5 = infos['md5']


	if(application_api_seq):	
		print "\n=======Analyzing behavior based on behavior report"
		analyze(malware_seq,application_api_seq)
	
	if(dlls):
		print "\n=======Analyzing behavior based on DLLs report"
		analyze(malware_seq,dlls)
		
	if(str):
		print "\n=======Analyzing behavior based on debug report"
		analyze(malware_seq,str)	
	
	# virus_total_report(md5)





	

    