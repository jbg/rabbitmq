from setuptools import setup, find_packages
from codecs import open
from os import path


here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='rabbitmq',
    version='0.2.0',
    description='CFFI bindings to librabbitmq 0.8.0',
    long_description=long_description,
    url='https://github.com/jbg/rabbitmq',
    author='Jasper Bryant-Greene',
    author_email='jbg@rf.net.nz',
    license='Apache-2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='rabbitmq amqp cffi',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=['cffi']
)
