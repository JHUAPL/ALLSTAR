import subprocess
from allstar import AllstarRepo
import os
from extract_functions import traverse

arch = 'amd64'

def downloadData():
	
	repo = AllstarRepo(arch)
	allstar_packages = repo.package_list()

	limit = 30
	for pkg in allstar_packages[:limit]:
	    binary_files = repo.package_binaries(pkg)
	    source_files = repo.package_source_code(pkg)

	    print(len(binary_files))
	    print(len(source_files))
	    print(pkg)
	    
	    for i in range(len(binary_files)):
	    	p = binary_files[i]
	    	q = source_files[i]
	    	if len(q['sources']) == 0:
	    		continue

	    	# binary_name = './allstar/' + arch + '/' + p['name'] + '.bin'
	    	# with open(binary_name, 'wb') as f:
	    	# 	f.write(p['content'])

	    	for s in q['sources']:
	    		if s['name'][2:].split('.')[-1][0] == 'c':
		    		source_name = './allstar/' + arch + '/' + q['name'] + '+' + s['name'][2:]
		    		with open(source_name, 'wb') as f:
		    			f.write(s['content'])

	    	# source_name = './allstar/' + arch + '/' + q['name'] + '.cpp'
	    	# with open(source_name, 'wb') as f:
	    	# 	for s in q['sources']:
	    	# 		f.write(s['content'])

def getDecompiledFunctions():
	mypath = './allstar/' + arch + '/'
	binaries = [os.path.join(mypath, f) for f in os.listdir(mypath) if f.split('.')[-1] == 'bin']
	for binary_name in binaries:
		print(binary_name)
		rc = subprocess.call('./generate_training_data.sh PrintFunctions.java ' + binary_name, shell=True)


import glob
import pdb

import multiprocessing
import numpy as np
import pickle


import clang.cindex
clang.cindex.Config.set_library_path('/Library/Developer/CommandLineTools/usr/lib/')

# find most of the functions
def getFuncFromCFile():
	mypath = './allstar/' + arch + '/'
	cfiles = [os.path.join(mypath, f) for f in os.listdir(mypath) if f.split('.')[-1][0] == 'c']

	# source_file = './allstar/amd64/9mount.cpp'
	for source_file in cfiles:

		found_functions = []
		with open(source_file, 'r', errors='replace') as fd:
			try:
				content = fd.read().splitlines()
				ode = '\n'.join(content)
				index = clang.cindex.Index.create()
				tu = index.parse(source_file, ['-E', '-x', 'c++'])
				objects = {"functions": [], "enums": [], "namespaces": [], "classes": [], "structs": []}
				traverse(tu.cursor, source_file, objects)
				found_functions = objects['functions']
			except: 
				print('%s unicode problem' % (source_file))

		corpus = []
		for func in found_functions:
			start_line = func.extent['start_line']
			end_line = func.extent['end_line']
			if start_line == end_line:
				continue
			else:
				corpus.append('\n'.join(content[start_line-1:end_line]))

		#print(source_file.split('/')[-1])
		dir = 'data/C/'+source_file.split('/')[-1].split('+')[0]
		#print(dir)
		if not os.path.exists(dir):
			os.mkdir(dir)

		for i, code in enumerate(corpus):

			print("-----")
			print(code)
			lines = code.split('\n')
			func_name = 'tmp'
			if len(lines[0].split(' ')) > 1:
				func_name = lines[0].split('(')[0].split(' ')[-1]
			else:
				func_name = lines[1].split('(')[0]

			invalid = False
			for c in ['<','>','*','/']:
				if c in func_name:
					invalid = True	
			if invalid:
				continue

			with open(dir + "/" + func_name + '.txt', 'wb') as f:
				f.write(code.encode())

import json
def parallel_data():
	mypath = './data/C'
	cpkg = [f for f in os.listdir(mypath) if os.path.isdir(os.path.join(mypath, f))]
	mypath = './data/GhidraCFull'
	gpkg = [f for f in os.listdir(mypath) if os.path.isdir(os.path.join(mypath, f))]

	data = []
	for pkg in gpkg:
		if pkg not in cpkg:
			continue
		gfuncs = [f for f in os.listdir('./data/GhidraCFull/'+pkg)]
		cfuncs = [f for f in os.listdir('./data/C/'+pkg)]
		for gf in gfuncs:
			if gf in cfuncs:
				pair = {'ghidra': '', 'c': ''}
				with open('./data/GhidraCFull/'+pkg+'/'+gf) as f:
					pair['ghidra'] = f.readlines()
				with open('./data/C/'+pkg+'/'+gf) as f:
					pair['c'] = f.readlines()
				data.append(pair)

	with open('./data/function_pairs_data.json', 'w') as outfile:
		json_data = {'data': data}
		json.dump(json_data, outfile)


'''
Download data from allstar website, the amount of data canbe changed by 'limit'.
For binary files, use headlessGhidra to de-compile them, save each function in a txt file.
For source files, use cparser to identify functions, save each function in a txt file.
Find corresponding de-compiled function and c fucntions, save in json.
'''
#downloadData()
#getDecompiledFunctions()
#getFuncFromCFile()
#parallel_data()

with open('./data/function_pairs_data.json', 'r') as f:
	strjson = f.read()
	data = json.loads(strjson)
	print(data['data'][0]['c'][:4])

