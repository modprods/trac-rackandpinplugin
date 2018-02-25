#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

VERSION = '1.2.2'
PACKAGE = 'rackandpin'

setup(
    name='TracRackAndPin',
    version=VERSION,
    description="OAuth2 authentication against Rack&Pin.",
    url='http://trac-hacks.org/wiki/TracRackAndPin',
    author='Michela Ledwidge',
    author_email='michela@mod.studio',
    keywords='trac plugin',
    license="Copyright (c) 2018, Mod Productions Pty Ltd",
    packages=[PACKAGE],
    include_package_data=True,
    package_data={},
    install_requires=["requests_oauthlib >=0.8.0"],
    entry_points={
        'trac.plugins': '%s = %s.api' % (PACKAGE, PACKAGE),
    },
    zip_safe=True,
)
