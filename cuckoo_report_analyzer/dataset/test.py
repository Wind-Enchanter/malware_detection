import csv
import json
import sys

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

def load_process_data():
	with open("../storage/win32_infostealer_Dexter.exe/processes.json", 'r') as f:
		processes_dict = json.load(f)
	return processes_dict



if __name__ == "__main__":

	processes = load_process_data()
	api_calls = []
	calls = processes['calls']
	for call in calls:
		api_calls.append(call['api'])
		
	# first_seq = data_reader.read_csv()
	
	application_api_seq = api_calls
	malware_seq = read_csv_malware_API()

	for malware_csv_rows in malware_seq:
		for api in application_api_seq:
			if api in malware_csv_rows:
				print api 
				print malware_csv_rows[0]