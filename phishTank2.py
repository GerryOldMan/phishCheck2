#!/usr/bin/python
'''
File:		phishTank.py
Date:		Jan 2019
Version:	0.2
Description:	Script to download and analyse data from phishtank.com. This script aims to 
		record new phishing websites to gather intelligence on the number spotted,
		how many use ssl, and what the main targets are.
'''

#Begin imports
import _pickle as pkl
import os
import dateutil.parser
import codecs
import csv
import requests

from contextlib import closing 
from datetime import datetime, timedelta

#Set the URL to obtain the data (This includes API key)
phishUrl = 'http://data.phishtank.com/data/0f8f9e7d641193fcb4c22a78c1db6c545d6cc2b0e39cad5c9f0453dd04418b7e/online-valid.csv'
current_time = datetime.now()

#Create the path to that months analysis
path = str(current_time.strftime('%Y')+'/'+current_time.strftime('%b')+'.pkl')

#Need to load previous analysis if it exists
try:
	analysis = pkl.load(open('path','rb'))
except:
	analysis = {'date': current_time-timedelta(days=1), 'ssl':0}


def get_data(phishUrl):
#stream=True avoids loading the entire file into memory before we start processing it, drastically reducing memory overhead for large files.
	
	data = []
	with closing(requests.get(phishUrl, stream=True)) as r:
		reader = csv.reader(codecs.iterdecode(r.iter_lines(), 'utf-8'), delimiter=',', quotechar='"')
		for row in reader:
			data.append(row)

	#Sort the data in to submission date order.
	#First need to pop the headings line
	data.pop(0)
	data.sort(key=lambda data: data[3], reverse=True)


	return data

def analyse(data, analysis):
	
	pos = 0
	now = datetime.now()
	while analysis['date'] < dateutil.parser.parse(data[pos][3][:-6]):
		if data[pos][1][:5] == 'https':
			analysis['ssl'] += 1
		if data[pos][-1] in analysis:
			analysis[data[pos][-1]] += 1
		else:
			analysis[data[pos][-1]] = 1
		pos += 1

	analysis['date'] = now
	return analysis

data = get_data(phishUrl)
analysis = analyse(data, analysis)

#Save the data
pickle.dump(analysis, open(path,'wb'))

#Now need to update the webpage.
#First sort the dictionary by the most phished sites
#To do this need to delete the date
del analysis['date']
sorted_analysis = sorted((value, key) for (key, value) in analysis.items())
sorted_analysis.reverse()

#Create the HTML


