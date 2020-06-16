from setuptools import setup, find_packages



setup(
    name='loglizer',
    version='1.0.0',
    url='https://github.com/logpai/loglizer',
    author='Ashok Rayal',
    description='Simple Log Management Toolkit',
    packages=find_packages(),    
    install_requires=['sklearn','pandas','torch'],
)
