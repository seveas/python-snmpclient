import os
from setuptools import setup
 
setup(name='python-snmpclient',
    version="0.4",
    description='Wrapper around pysnmp4 for easier snmp querying',
    author='Dennis Kaarsemaker',
    author_email='dennis@kaarsemaker.net',
    py_modules=['snmpclient'],
    url='http://github.com/seveas/python-snmpclient',
    classifiers=[
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Operating System :: OS Independent",
        "Topic :: System :: Monitoring",
        "Topic :: Software Development"
    ],
    #install_requires='pysnmp',
)
