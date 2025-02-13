#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

VERSION = '1.6'
PACKAGE = 'rackandpin'

setup(
    name='RackAndPin',
    version=VERSION,
    description="OAuth2 authentication against Rack&Pin.",
    url='http://trac-hacks.org/wiki/TracRackAndPin',
    author='Michela Ledwidge',
    author_email='michela@mod.studio',
    keywords='trac plugin',
    license="Copyright (C) 2025, Mod Productions Pty Ltd",
    packages=[PACKAGE],
    include_package_data=True,
    package_data={},
    install_requires=[
        "requests_oauthlib >=0.8.0",
        "certifi>=2025.1.31"
    ],
    entry_points={
        'trac.plugins': '%s = %s.api' % (PACKAGE, PACKAGE),
    },
    zip_safe=True,
)
