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

import json
import requests
from urllib.parse import urljoin
from collections import defaultdict
from . import util
from .error import AllstarPackageError

BASE_URL = "https://allstar.jhuapl.edu"


class Repo(object):
    """A Repo represents an architecture repository of the ALLSTAR dataset.

    The ALLSTAR site will return JSON information about the repository and
    all packages in that repository. This class is a simple wrapper that
    can query the appropriate URLs and return Python objects.

    Example:
       r = Repo('amd64')
       for pkg in r.package_list():
           for binary in r.package_binaries(pkg):
               process(binary)
    """

    def __init__(self, arch, base_url=BASE_URL):
        """Inits Repo class for a specified architecture.

        Args:
            arch: Architecture to query. Valid architectures are:
                'amd64', 'armel', 'i386', 'mipsel', 'ppc64el', and 's390x'
        """
        self.arch = arch
        self.base_url = base_url
        self.rsession = requests.Session()

        self.packages_by_name = {}
        self.packages_by_part = defaultdict(list)
        self._generate_package_list()

    def _generate_package_list(self):
        for part in range(1, 5):
            url = urljoin(self.base_url,
                          '/repo/jessie-list-p{}-final.txt'.format(part))
            r = self.rsession.get(url)

            for pkg in r.text.split():
                self.packages_by_name[pkg] = part
                self.packages_by_part[part].append(pkg)

    def packages(self):
        """Get a list of all packages that are in the repo.

        Returns:
            A list of strings with the names of all packages.
        """
        return list(self.packages_by_name.keys())

    def package(self, pkg):
        return Package(pkg, self.arch,
                       self.base_url)


class Package(object):
    """A Package represents a package in the ALLSTAR dataset.
    """

    def __init__(self, name, arch, base_url=BASE_URL):
        self.name = name
        self.arch = arch
        self.part = util.package_part(self.name)
        self.base = urljoin(base_url,
                            f'/repo/p{self.part}/{self.arch}/{self.name}/')

        self.rsession = requests.Session()
        index_url = urljoin(self.base, 'index.json')
        resp = self.rsession.get(index_url)
        if resp.status_code == 404:
            raise AllstarPackageError(f'No such package: {self.name}')
        index_json = resp.text
        try:
            self.index = json.loads(index_json)
        except json.JSONDecodeError:
            index_json = self._fix_index(index_json)
            self.index = json.loads(index_json)

        self.documentation = self.index['documentation']
        self.binaries = self.index['binaries']

    def _fix_index(self, index):
        """Deal with buggy json generation from ALLSTAR
        where having multiple "manual" entries was improperly handled.
        Have to change multiple "manual" entries to a json list
        """
        index_offset = 0

        while True:
            mans_start = index.find('"manual": ', index_offset)
            if mans_start == -1:
                break
            mans_start = mans_start + len('"manual": ')

            # Need to skip the '"' that's at start
            mans_end = index.find('"', mans_start + 1)
            if mans_end == -1:
                break
            # Want the '"' at the end
            mans_end = mans_end + 1

            mans = index[mans_start:mans_end]
            fixed_mans = '",\n"'.join(mans.split('\n'))
            index = f'{index[:mans_start]} [ {fixed_mans} ]\n {index[mans_end:]}'

            index_offset = mans_end

        return index

    def has_binaries(self):
        return len(self.binaries) > 0

    def get_binaries(self):
        ret = []
        for b in self.binaries:
            name = b['name']
            url = urljoin(self.base, f'{name}')
            r = self.rsession.get(url)
            ret.append({'name': name,
                        'content': r.content})
        return ret

    def get_gimples(self):
        ret = []
        for b in self.binaries:
            for u in b['units']:
                if 'gimple' in u:
                    name = u['gimple']
                    url = urljoin(self.base, name)
                    r = self.rsession.get(url)
                    ret.append({'name': name,
                                'content': r.content})
        return ret
