#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from setuptools import setup
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = [
            '--doctest-modules',
            '--strict',
        ]

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)

setup(
    name="tuf_tap7_vectors",
    version="0.0.0",
    author="heartsucker",
    author_email="heartsucker@autistici.org",
    description="Serves TUF/Uptane test vectors",
    cmdclass={'test': PyTest},
)
