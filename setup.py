# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

from setuptools import setup

setup(
    name='tufrepo',
    version='0.1.0',
    py_modules=['tufrepo'],
    install_requires=[
        'Click',
        'securesystemslib[pynacl]',
        'tuf',
    ],
    entry_points={
        'console_scripts': [
            'tufrepo = tufrepo:cli',
        ],
    },
)
