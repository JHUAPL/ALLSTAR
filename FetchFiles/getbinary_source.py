import subprocess
from allstar import AllstarRepo
import os

arch = 'amd64'
repo = AllstarRepo(arch)
allstar_packages = repo.package_list()

limit = 100
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

    	binary_name = 'C:/MINDSIGHT/ALLSTAR/bin/' + arch + '/' + p['name'] + '.bin'
    	with open(binary_name, 'wb') as f:
    		f.write(p['content'])

    	source_name = 'C:/MINDSIGHT/ALLSTAR/src/' + arch + '/' + q['name'] + '.cpp'
    	with open(source_name, 'wb') as f:
    		for s in q['sources']:
    			f.write(s['content'])

#rc = subprocess.call('./generate_training_data.sh ASTGenerator.java ' + binary_name, shell=True)