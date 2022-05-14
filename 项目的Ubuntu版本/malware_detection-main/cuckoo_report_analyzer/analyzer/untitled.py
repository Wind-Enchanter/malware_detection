import csv
import json
import sys
import virustotal

def read_csv():
	dataSet = []
	with open("/malware_API_dataset.csv", "rb") as stream:
		reader = csv.reader(stream, delimiter=',')
		reader.next() # ignoring header
		for rowdata in reader:
			if len(rowdata) > 0:
				dataSet.append(rowdata)
	return dataSet	


def read_csv_malware_API():
	dataSet = []
	with open("malware_API_calls.csv", "rb") as stream:
		reader = csv.reader(stream, delimiter=',')
		reader.next() # ignoring header
		for rowdata in reader:
			if len(rowdata) > 0:
				dataSet.append(rowdata)
	return dataSet		

def load_info():
	with open("executable_info.json", 'r') as f:
		info_dict = json.load(f)
	return info_dict

def load_process_data():
	with open("processes.json", 'r') as f:
		processes_dict = json.load(f)
	return processes_dict

def delete_duplicate(array):
	output = []
	for val in array:
		if not val in output:
			output.append(val)
	return output		


VT_API_KEY = "c6897aa50129b40c32139ed2ebe53214139eeb9068f87b43584e6016eb853932"

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
	count = 0

	for match in matches:
		if (int(match[1])>=7):
			count+=1
			print "Menemukan "+str(count)+" malicious behavior"	
			temp.append(match)	
	if (temp):
		print "\n=======FILE ADALAH MALWARE=======\n"	
		print "Karena melakukan hal berikut :"
		for match in matches:
			if (int(match[1])>=7):
				print "Behavior :	" + match[0]
				print "Score 	:	" + match[1]
				print "Functions:" 
				for func in match[2]:
					print "	"+func
	else :
		print "\n=======FILE TIDAK MALWARE=======\n"	
						

if __name__ == "__main__":


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

	# virus_total_report(md5)
	

	processes = load_process_data()
	api_calls = []
	calls = processes['calls']
	for call in calls:
		api_calls.append(call['api'])
		
	# first_seq = data_reader.read_csv()
	
	application_api_seq = api_calls
	malware_seq = read_csv_malware_API()

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

			print match_api
			temp = match_api
			matches.append([malware_csv_rows[0],malware_csv_rows[1],temp])
		
		match_api = []

	count_score(matches)	
	


