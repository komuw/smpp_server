import os
from setuptools import setup, find_packages


def read_file(filename):
    filepath = os.path.join(os.path.dirname(__file__), filename)
    return open(filepath, 'r').read()

setup(
    name="smpp_server",
    version="0.1.0",
    url='https://github.com/komuW/smpp_server',
    license='BSD',
    description="Python SMPP Library",
    long_description=read_file('README.rst'),
    author='komuW',
    author_email='komuw05@gmail.com',
    packages=find_packages(),
    install_requires=[
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
