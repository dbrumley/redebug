#!/usr/bin/env python
#
# redebug.py
#
# Jiyong Jang, 2012
#
import sys
import os
import re
import time
import common
import patchloader
import sourceloader
import reporter

try:
    import argparse
    import magic
except ImportError as err:
    print err
    sys.exit(-1)


def parse_args():
    '''
    Parse command line arguments
    '''
    parser = argparse.ArgumentParser()
    # optional arguments
    parser.add_argument('-n', '--ngram',\
            action='store', dest='ngram_size', type=int, default=4, metavar='NUM',\
            help='use n-gram of NUM lines (default: %(default)s)')
    parser.add_argument('-c', '--context',\
            action='store', dest='context_line', type=int, default=10, metavar='NUM',\
            help='print NUM lines of context (default: %(default)s)')
    parser.add_argument('-v', '--verbose',\
            action='store_true', dest='verbose_mode', default=False,\
            help='enable verbose mode (default: %(default)s)')
    # positional arguments
    parser.add_argument('patch_path', action='store', help='path to patch files (in unified diff format)')
    parser.add_argument('source_path', action='store', help='path to source files')

    try:
        args = parser.parse_args()
        common.ngram_size = args.ngram_size
        common.context_line = args.context_line
        common.verbose_mode = args.verbose_mode
        return args.patch_path, args.source_path
    except IOError, msg:
        parser.error(str(msg))


if __name__ == '__main__':

    # parse arguments
    start_time = time.time()
    patch_path, source_path = parse_args()
    common.verbose_print('[-] ngram_size   : %d' % common.ngram_size)
    common.verbose_print('[-] context_line : %d' % common.context_line)
    common.verbose_print('[-] verbose_mode : %s' % common.verbose_mode)
    common.verbose_print('[-] patch_path   : %s' % patch_path)
    common.verbose_print('[-] source_path  : %s' % source_path)

    # initialize a magic cookie pointer
    try:
        common.magic_cookie = magic.open(magic.MAGIC_MIME)
        common.magic_cookie.load()
    except AttributeError:
        common.magic_cookie = magic.Magic(mime=True, uncompress=True)
    common.verbose_print('[-] initialized magic cookie\n')

    # traverse patch files
    patch = patchloader.PatchLoader()
    npatch = patch.traverse(patch_path)
    if npatch == 0:
        print('[!] no patch to be queried')
        sys.exit(1)

    # traverse source files
    source = sourceloader.SourceLoader()
    nmatch = source.traverse(source_path, patch)
    if nmatch == 0:
        print('[!] no match to be checked')
        sys.exit(1)

    # generate a report
    report = reporter.Reporter(patch, source)
    exact_nmatch = report.output()
    if exact_nmatch == 0:
        print('[!] no exact match found')
        sys.exit(1)

    elapsed_time = time.time() - start_time
    print '[+] %d matches given %d patches ... %.1fs' % (exact_nmatch, npatch, elapsed_time)

