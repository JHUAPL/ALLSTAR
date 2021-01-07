import allstar
import subprocess

repo = allstar.AllstarRepo("amd64")
allstar_packages = repo.package_list()


for pkg in allstar_packages[:100]:
    binary_files = repo.package_binaries(pkg)
    for p in binary_files:
        print(p['name'])
        binary_name = 'C:/MINDSIGHT/ALLSTAR/tmp/' + p['name'] + '.bin'
        with open(binary_name, 'wb') as f:
            f.write(p['content'])