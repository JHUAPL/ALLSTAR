##############################################################################################
# Copyright 2020 The Johns Hopkins University Applied Physics Laboratory LLC
# All rights reserved.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this 
# software and associated documentation files (the "Software"), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, 
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE 
# OR OTHER DEALINGS IN THE SOFTWARE.
#
# HAVE A NICE DAY.

import requests
from urllib.parse import urljoin
import json

#class for interacting with ALLSTAR repository
#can use alternate URL if you have cloned ALLSTAR locally

#Example:
#import allstar
#
#repo = allstar.AllstarRepo("armel")
#for pkg in repo.packages():
#  for b in pkg.binaries():

class AllstarRepo(object):
    def __init__(self, arch, base_url='https://allstar.jhuapl.edu'):
        self.arch = arch
        self.base_url = base_url
        self.rsession = requests.Session()


        self.packages = {}
        self._generate_package_list()

    def _generate_package_list(self):
        for part in range(1,5):
            url = urljoin(self.base_url, '/repo/jessie-list-p{}-final.txt'.format(part))
            r = self.rsession.get(url)

            for pkg in r.text.split():
                self.packages[pkg] = part


    def _package_part(self, pkg):
        return self.packages[pkg]

    def _package_index(self, pkg):
        pkg_url = urljoin(self.base_url, '/repo/p{}/{}/{}/'.format(self._package_part(pkg),
                                                                   self.arch, pkg))
        index_url = urljoin(pkg_url, 'index.json')
        return self.rsession.get(index_url).json(strict=False)

    def package_list(self):
        return list(self.packages.keys())


    def package_source_code(self, pkg):
        sources = []
        index = self._package_index(pkg)

        for i in range(0, len(index['binaries'])):
            pieces = []
            for j in range(0, len(index['binaries'][i]['units'])):
                u = index['binaries'][i]['units'][j]
                if 'source' in u:
                    sf = index['binaries'][i]['units'][j]['source'][2:]
                    source_url = urljoin(self.base_url, 
                                        '/repo/p{}/{}/{}/{}'.format(self._package_part(pkg),
                                                             self.arch, pkg, sf))
                    r = self.rsession.get(source_url)
                    pieces.append({'name': index['binaries'][i]['units'][j]['source'],
                                'content': r.content})
            sources.append({'name': index['binaries'][i]['name'],
                                'sources': pieces})
        return sources

    # Similar to package_binaries except that this only checks for the
    # existence of binaries by downloading the headers rather than the entire binaries
    # Returns a list of booleans where len(list) is the number of binaries found
    def package_binaries_exist(self, pkg):
        binaries = []
        index = self._package_index(pkg)

        for i in range(0, len(index['binaries'])):
            f = index['binaries'][i]['file']
            binary_url = urljoin(self.base_url,
                                 '/repo/p{}/{}/{}/{}'.format(self._package_part(pkg),
                                                             self.arch, pkg, f))
            r = self.rsession.head(binary_url)
            if r:
                binaries.append(True)
            else:
                binaries.append(False)
        return binaries

    def package_binaries(self, pkg):
        binaries = []
        index = self._package_index(pkg)

        for i in range(0, len(index['binaries'])):
            f = index['binaries'][i]['file']
            binary_url = urljoin(self.base_url,
                                 '/repo/p{}/{}/{}/{}'.format(self._package_part(pkg),
                                                             self.arch, pkg, f))
            #print(binary_url)
            r = self.rsession.get(binary_url)
            binaries.append({'name': index['binaries'][i]['name'],
                             'content': r.content})

        return binaries

    def download_arm_binaries(self,pkg):
        binaries = []
        index = self._package_index(pkg)

        # if index["arch"] != "arm":
        #     print(index["package"], index["arch"])
        #     return binaries
        print(index["arch"])
        return []

        for i in range(0, len(index['binaries'])):
            f = index['binaries'][i]['file']
            binary_url = urljoin(self.base_url,
                                 '/repo/p{}/{}/{}/{}'.format(self._package_part(pkg),
                                                             self.arch, pkg, f))
            r = self.rsession.head(binary_url)
            binaries.append({'name': index['binaries'][i]['name'],
                             'content': r.content})
        return binaries



    def package_gimples(self, pkg):
        gimples = []
        index = self._package_index(pkg)

        for i in range(0, len(index['binaries'])):
            for j in range(0, len(index['binaries'][i]['units'])):
                if('gimple' in index['binaries'][i]['units'][j]):
                    g = index['binaries'][i]['units'][j]['gimple']
                    gimple_url = urljoin(self.base_url,
                        '/repo/p{}/{}/{}/{}'.format(self._package_part(pkg),
                                                    self.arch,
                                                    pkg,
                                                    g))
                    r = self.rsession.get(gimple_url)
                    gimples.append({'name': index['binaries'][i]['units'][j]['name'],
                                    'content': r.content})
            
        return gimples
