from setuptools import setup, find_packages


def readme():
  with open('README.md', 'r') as f:
    return f.read()


setup(
  name='swp',
  version='0.0.1',
  author='Sekret',
  author_email='asinskijp188@gmail.com',
  description='protocol for wrapping packets',
  long_description=readme(),
  long_description_content_type='text/markdown',
  packages=find_packages(include=['sekret_wrapper_protocol', 'sekret_wrapper_protocol.*']),
  install_requires=[
    'cryptography>=48.0.0',
    ],
  classifiers=[
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Programming Language :: Python :: 3.10',
    'Programming Language :: Python :: 3.11',
    'Programming Language :: Python :: 3.12',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
  ],
  python_requires='>=3.8',
  url='https://github.com/sekret01/SWP',
)