#!/bin/bash
python setup.py sdist bdist_wheel
twine upload --repository pypi dist/*
rm -rf src/secshrnet.egg-info
rm -rf dist
rm -rf build
