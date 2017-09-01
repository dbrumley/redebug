# ReDeBug
Unpatched code clone detection tool - reimplemented version in Python.

Please refer to our [IEEE S&P research paper](http://ieeexplore.ieee.org/document/6234404) and [USENIX ;login: article](https://www.usenix.org/publications/login/december-2012-volume-37-number-6/redebug-finding-unpatched-code-clones-entire-os) for technical details.

_Note that this is a reimplemented version in Python for usability and adaptability, and different from the original faster C implementation used in IEEE S&P evaluation._

## Dependencies
- `bitarray`, `python-magic`, and `argparse` modules: `pip install bitarray python-magic argparse`
- `libmagic` package: `apt-get install libmagic-dev` on Ubuntu/Debian, `brew install libmagic` on OSX

## Usage
Please refer to the help message for options:
```
$ python redebug.py -h
usage: redebug.py [-h] [-n NUM] [-c NUM] [-v] patch_path source_path

positional arguments:
  patch_path            path to patch files (in unified diff format)
  source_path           path to source files

optional arguments:
  -h, --help            show this help message and exit
  -n NUM, --ngram NUM   use n-gram of NUM lines (default: 4)
  -c NUM, --context NUM
                        print NUM lines of context (default: 10)
  -v, --verbose         enable verbose mode (default: False)
```
