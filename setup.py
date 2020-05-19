# Always prefer setuptools over distutils
from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Get all dependencies from requirements.txt
with open(path.join(here, 'requirements.txt')) as f:
    required_packages = f.read().strip().split('\n')
    print(required_packages)

setup(
    name='secshrnet',  # Required
    version='0.5.5',  # Required
    description='Secret sharing over a distributed network',  # Optional
    long_description=long_description,  # Optional
    long_description_content_type='text/markdown',  # Optional (see note above)
    url='https://github.com/dmhacker/secshrnet',  # Optional
    author='David Hacker',  # Optional
    author_email='dmhacker@protonmail.com',  # Optional
    classifiers=[  # Optional
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Pick your license as you wish
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate you support Python 3. These classifiers are *not*
        # checked by 'pip install'. See instead 'python_requires' below.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3 :: Only',
    ],
    keywords='secret sharing network cryptography',  # Optional
    package_dir={'': '.'},  # Optional
    packages=find_packages(where='.'),  # Required
    python_requires='>=3.5, <4',
    install_requires=required_packages,  # Optional
    # For example, the following would provide a command called `sample` which
    # executes the function `main` from this package when invoked:
    entry_points={  # Optional
        'console_scripts': [
            'secshrnetc=secshrnet:client.main',
            'secshrnetd=secshrnet:server.main',
        ],
    },
)
