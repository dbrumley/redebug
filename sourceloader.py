# sourceloader.py
#   SourceLoader class
#
# Jiyong Jang, 2012
#
import sys
import os
import re
import time
from collections import defaultdict
import common

try:
    import bitarray
except ImportError as err:
    print err
    sys.exit(-1)


class SourceLoader(object):

    def __init__(self):
        self._patch_list = []
        self._npatch = 0
        self._source_list = []
        self._nsource = 0
        self._match_dict = defaultdict(list)
        self._nmatch = 0
        self._bit_vector = bitarray.bitarray(common.bloomfilter_size)

    def traverse(self, source_path, patch):
        '''
        Traverse source files
        '''
        print '[+] traversing source files'
        start_time = time.time()
        self._patch_list = patch.items()
        self._npatch = patch.length()

        if os.path.isfile(source_path):
            magic_type = common.file_type(source_path)
            common.verbose_print('  [-] %s: %s' % (source_path, magic_type))
            if magic_type.startswith('text'):
                main_type, sub_type = magic_type.split('/')
                magic_ext = self._get_file_type(sub_type)
                self._process(source_path, magic_ext)
        elif os.path.isdir(source_path):
            for root,dirs,files in os.walk(source_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    magic_type = common.file_type(file_path)
                    common.verbose_print('  [-] %s: %s' % (file_path, magic_type))
                    if magic_type.startswith('text'):
                        main_type, sub_type = magic_type.split('/')
                        magic_ext = self._get_file_type(sub_type)
                        self._process(file_path, magic_ext)

        elapsed_time = time.time() - start_time
        print '[+] %d possible matches ... %.1fs\n' % (self._nmatch, elapsed_time)
        return self._nmatch

    def _process(self, source_path, magic_ext):
        '''
        Normalize a source file and build a Bloom filter for queries
        '''
        source_file = open(source_path, 'r')
        source_orig_lines = source_file.read()
        source_file.close()

        source_norm_lines = self._normalize(source_orig_lines, magic_ext)
        if self._query_bloomfilter(source_norm_lines, magic_ext):
            source_norm_lines = re.split('\n', source_norm_lines)
            source_orig_lines = re.split('\n', source_orig_lines)
            self._source_list.append(common.SourceInfo(source_path, magic_ext, source_orig_lines, source_norm_lines))
            self._nsource += 1

    def _normalize(self, source, ext):
        '''
        Normalize a source file
        '''
        # Language-specific optimization
        if ext==common.FileExt.C or ext==common.FileExt.Java:
            norm_lines = []
            for c in common.c_regex.finditer(source):
                if c.group('noncomment'):
                    norm_lines.append(c.group('noncomment'))
                elif c.group('multilinecomment'):
                    newlines_cnt = c.group('multilinecomment').count('\n')
                    while newlines_cnt:
                        norm_lines.append('\n')
                        newlines_cnt -= 1
            source = ''.join(norm_lines)
        elif ext==common.FileExt.ShellScript or ext==common.FileExt.Python:
            source = ''.join([c.group('noncomment') for c in common.shellscript_regex.finditer(source) if c.group('noncomment')])
        elif ext==common.FileExt.Perl:
            source = ''.join([c.group('noncomment') for c in common.perl_regex.finditer(source) if c.group('noncomment')])
        elif ext==common.FileExt.PHP:
            norm_lines = []
            for c in common.php_regex.finditer(source):
                if c.group('noncomment'):
                    norm_lines.append(c.group('noncomment'))
                elif c.group('multilinecomment'):
                    newlines_cnt = c.group('multilinecomment').count('\n')
                    while newlines_cnt:
                        norm_lines.append('\n')
                        newlines_cnt -= 1
            source = ''.join(norm_lines)
        elif ext==common.FileExt.Ruby:
            norm_lines = []
            for c in common.ruby_regex.finditer(source):
                if c.group('noncomment'):
                    norm_lines.append(c.group('noncomment'))
                elif c.group('multilinecomment'):
                    newlines_cnt = c.group('multilinecomment').count('\n')
                    while newlines_cnt:
                        norm_lines.append('\n')
                        newlines_cnt -= 1
            source = ''.join(norm_lines)

        # Remove whitespaces except newlines
        source = common.whitespaces_regex.sub("", source)
        # Convert into lowercases
        return source.lower()

    def _query_bloomfilter(self, source_norm_lines, magic_ext):
        source_norm_lines = source_norm_lines.split()
        if len(source_norm_lines) < common.ngram_size:
            common.verbose_print('      - skipped (%d lines)' % len(source_norm_lines))
            return False

        self._bit_vector.setall(0)
        num_ngram = len(source_norm_lines) - common.ngram_size + 1
        is_vuln_source = False
        num_ngram_processed = 0
        for i in range(0, num_ngram):
            if num_ngram_processed > common.bloomfilter_size/common.min_mn_ratio:
                common.verbose_print('      - split Bloom filters (%d n-grams)' % num_ngram_processed)
                for patch_id in range(0, self._npatch):
                    if magic_ext == self._patch_list[patch_id].file_ext:
                        hash_list = self._patch_list[patch_id].hash_list
                        is_match = True
                        for h in hash_list:
                            if not self._bit_vector[h]:
                                is_match = False
                                break
                        if is_match:
                            is_vuln_source = True
                            self._match_dict[patch_id].append(self._nsource)
                            common.verbose_print('      - match (patch #%d : source #%d)' % (patch_id, self._nsource))
                            self._nmatch += 1
                num_ngram_processed = 0
                self._bit_vector.setall(0)

            ngram = ''.join(source_norm_lines[i:i+common.ngram_size])
            hash1 = common.fnv1a_hash(ngram) & (common.bloomfilter_size-1)
            hash2 = common.djb2_hash(ngram) & (common.bloomfilter_size-1)
            hash3 = common.sdbm_hash(ngram) & (common.bloomfilter_size-1)
            self._bit_vector[hash1] = 1
            self._bit_vector[hash2] = 1
            self._bit_vector[hash3] = 1
            num_ngram_processed += 1

        for patch_id in range(0, self._npatch):
            if magic_ext == self._patch_list[patch_id].file_ext:
                hash_list = self._patch_list[patch_id].hash_list
                is_match = True
                for h in hash_list:
                    if not self._bit_vector[h]:
                        is_match = False
                        break
                if is_match:
                    is_vuln_source = True
                    self._match_dict[patch_id].append(self._nsource)
                    common.verbose_print('      - match (patch #%d : source #%d)' % (patch_id, self._nsource))
                    self._nmatch += 1

        return is_vuln_source

    def _get_file_type(self, sub_type):
        '''
        Determine a file type based upon sub_type (magic module)
        '''
        magic_ext = None
        if sub_type.startswith('x-c'):
            magic_ext = common.FileExt.C
        elif sub_type == 'x-java':
            magic_ext = common.FileExt.Java
        elif sub_type == 'x-shellscript':
            magic_ext = common.FileExt.ShellScript
        elif sub_type == 'x-perl':
            magic_ext = common.FileExt.Perl
        elif sub_type == 'x-python':
            magic_ext = common.FileExt.Python
        elif sub_type == 'x-php':
            magic_ext = common.FileExt.PHP
        elif sub_type == 'x-ruby':
            magic_ext = common.FileExt.Ruby
        else:
            magic_ext = common.FileExt.Text
        return magic_ext

    def items(self):
        return self._source_list

    def length(self):
        return self._nsource

    def match_items(self):
        return self._match_dict

