#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

VERSION = '0.1'
PACKAGE = 'tracrackandpin'

setup(
    name='RackAndPin',
    version=VERSION,
    description="Lists components based on a name.",
    url='http://trac-hacks.org/wiki/ComponentsProcessorMacro',
    author='Michela Ledwidge',
    author_email='michela@mod.studio',
    keywords='trac plugin',
    license="?",
    packages=[PACKAGE],
    include_package_data=True,
    package_data={},
    install_requires=["requests_oauthlib >=0.8.0"],
    entry_points={
        'trac.plugins': '%s = %s.api' % (PACKAGE, PACKAGE),
    },
    zip_safe=True,
)
