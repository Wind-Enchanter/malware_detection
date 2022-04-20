import csv

def read_csv():
	dataSet = []
	with open("./dataset/malware_API_dataset.csv", "rb") as stream:
		reader = csv.reader(stream, delimiter=',')
		reader.next() # ignoring header
		for rowdata in reader:
			if len(rowdata) > 0:
				dataSet.append(rowdata)
	return dataSet	


def read_csv_malware_API():
	dataSet = []
	with open("./dataset/malware_API_calls2.csv", "rb") as stream:
		reader = csv.reader(stream, delimiter=',')
		reader.next() # ignoring header
		for rowdata in reader:
			if len(rowdata) > 0:
				dataSet.append(rowdata)
	return dataSet			  					  		