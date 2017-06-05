# common.py
#   common variables and functions
#
# Jiyong Jang, 2012
#
import os
import re
from collections import namedtuple


# global variables
ngram_size   = 4
context_line = 10
verbose_mode = False
magic_cookie = None
bloomfilter_size = 2097152
min_mn_ratio = 32

PatchInfo = namedtuple('PatchInfo',\
        ['file_path', 'file_ext', 'orig_lines', 'norm_lines', 'hash_list'])
SourceInfo = namedtuple('SourceInfo',\
        ['file_path', 'file_ext', 'orig_lines', 'norm_lines'])
ContextInfo = namedtuple('ContextInfo',\
        ['source_id', 'prev_context_line', 'start_line', 'end_line', 'next_context_line'])

class FileExt:
    NonText     = 0
    Text        = 1
    C           = 2
    Java        = 3
    ShellScript = 4
    Python      = 5
    Perl        = 6
    PHP         = 7
    Ruby        = 8

# html escape chracters
html_escape_dict = { '&': '&amp;', '>': '&gt;', '<': '&lt;', '"': '&quot;', '\'': '&apos;' }

# regex for comments
c_regex = re.compile(r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"{}]*)', re.DOTALL | re.MULTILINE)
c_partial_comment_regex = re.compile(r'(?P<comment>/\*.*?$|^.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"{}]*)', re.DOTALL)
shellscript_regex = re.compile(r'(?P<comment>#.*?$)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^#\'"]*)', re.DOTALL | re.MULTILINE)
perl_regex = re.compile(r'(?P<comment>#.*?$|[{}]+)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^#\'"{}]*)', re.DOTALL | re.MULTILINE)
php_regex = re.compile(r'(?P<comment>#.*?$|//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^#/\'"{}]*)', re.DOTALL | re.MULTILINE)
ruby_regex = re.compile(r'(?P<comment>#.*?$)|(?P<multilinecomment>=begin.*?=end)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^#=\'"]*)', re.DOTALL | re.MULTILINE)
ruby_partial_comment_regex = re.compile(r'(?P<comment>=begin.*?$|^.*?=end)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^#=\'"]*)', re.DOTALL)

# regex for whitespaces except newlines
whitespaces_regex = re.compile(r'[\t\x0b\x0c\r ]+')


def file_type(file_path):
    try:
        return magic_cookie.from_file(file_path)
    except AttributeError:
        return magic_cookie.file(file_path)

def verbose_print(text):
    if verbose_mode:
        print '%s' % text

def fnv1a_hash(string):
    '''
    FNV-1a 32bit hash (http://isthe.com/chongo/tech/comp/fnv/)
    '''
    hash = 2166136261
    for c in string:
        hash ^= ord(c)
        hash *= 16777619
        hash &= 0xFFFFFFFF
    return hash

def djb2_hash(string):
    '''
    djb2 hash (http://www.cse.yorku.ca/~oz/hash.html)
    '''
    hash = 5381
    for c in string:
        hash = ((hash << 5) + hash) + ord(c)
        hash &= 0xFFFFFFFF
    return hash

def sdbm_hash(string):
    '''
    sdbm hash (http://www.cse.yorku.ca/~oz/hash.html)
    '''
    hash = 0
    for c in string:
        hash = ord(c) + (hash << 6) + (hash << 16) - hash
        hash &= 0xFFFFFFFF
    return hash


'''
http://programmers.stackexchange.com/questions/49550/which-hashing-algorithm-is-best-for-uniqueness-and-speed
http://www.partow.net/programming/hashfunctions/index.html
'''

