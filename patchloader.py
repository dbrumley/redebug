# patchloader.py
#   PatchLoader class
#
# Jiyong Jang, 2012
#
import os
import re
import time
import mimetypes
import common


class PatchLoader(object):

    def __init__(self):
        self._patch_list = []
        self._npatch = 0

    def traverse(self, patch_path):
        '''
        Traverse patch files
        '''
        print '[+] traversing patch files'
        start_time = time.time()

        if os.path.isfile(patch_path):
            magic_type = common.file_type(patch_path)
            common.verbose_print('  [-] %s: %s' % (patch_path, magic_type))
            if magic_type.startswith('text'):
                main_type, sub_type = magic_type.split('/')
                self._process(patch_path)
        elif os.path.isdir(patch_path):
            for root,dirs,files in os.walk(patch_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    magic_type = common.file_type(file_path)
                    common.verbose_print('  [-] %s: %s' % (file_path, magic_type))
                    if magic_type.startswith('text'):
                        main_type, sub_type = magic_type.split('/')
                        self._process(file_path)
        self._npatch = len(self._patch_list)

        elapsed_time = time.time() - start_time
        print '[+] %d patches ... %.1fs\n' % (self._npatch, elapsed_time)
        return self._npatch

    def _process(self, patch_path):
        '''
        Normalize a patch file and build a hash list
        '''
        patch_filename = patch_path.split('/')[-1]
        patch_file = open(patch_path, 'r')
        patch_lines = patch_file.readlines()
        patch_file.close()
        magic_ext = None
        process_flag = False
        diff_file = ''
        diff_cnt = 0
        diff_vuln_lines = []
        diff_orig_lines = []

        for line in patch_lines:
            if line.startswith('--- '):
                if diff_vuln_lines:
                    diff_norm_lines = self._normalize(''.join(diff_vuln_lines), magic_ext).split()
                    if len(diff_norm_lines) >= common.ngram_size:
                        common.verbose_print('      %s %d (ext: %d)' % (diff_file, diff_cnt, magic_ext))
                        path = '[%s] %s #%d' % (patch_filename, diff_file, diff_cnt)
                        hash_list = self._build_hash_list(diff_norm_lines)
                        self._patch_list.append(common.PatchInfo(path, magic_ext, ''.join(diff_orig_lines), diff_norm_lines, hash_list))
                    else:
                        common.verbose_print('      %s %d (ext: %d) - skipped (%d lines)' % (diff_file, diff_cnt, magic_ext, len(diff_norm_lines)))
                    del diff_vuln_lines[:]
                    del diff_orig_lines[:]

                diff_path = line.split()[1]
                if diff_path == '/dev/null':
                    process_flag = False
                else:
                    process_flag = True
                    diff_cnt = 0
                    diff_file = diff_path.split('/')[-1]
                    magic_ext = self._get_file_type(diff_file)

            elif process_flag:
                if line.startswith('+++ '):
                    diff_path = line.split()[1]
                    if diff_path == '/dev/null':
                        process_flag = False

                elif line.startswith('@@'):
                    if diff_vuln_lines:
                        diff_norm_lines = self._normalize(''.join(diff_vuln_lines), magic_ext).split()
                        if len(diff_norm_lines) >= common.ngram_size:
                            common.verbose_print('      %s %d (ext: %d)' % (diff_file, diff_cnt, magic_ext))
                            path = '[%s] %s #%d' % (patch_filename, diff_file, diff_cnt)
                            hash_list = self._build_hash_list(diff_norm_lines)
                            self._patch_list.append(common.PatchInfo(path, magic_ext, ''.join(diff_orig_lines), diff_norm_lines, hash_list))
                        else:
                            common.verbose_print('      %s %d (ext: %d) - skipped (%d lines)' % (diff_file, diff_cnt, magic_ext, len(diff_norm_lines)))
                        del diff_vuln_lines[:]
                        del diff_orig_lines[:]
                    diff_cnt += 1

                elif line.startswith('-'):
                    diff_vuln_lines.append(line[1:])
                    diff_orig_lines.append('<font color=\"#AA0000\">')
                    diff_orig_lines.append(line.replace('<','&lt;').replace('>','&gt;'))
                    diff_orig_lines.append('</font>')

                elif line.startswith('+'):
                    diff_orig_lines.append('<font color=\"#00AA00\">')
                    diff_orig_lines.append(line.replace('<','&lt;').replace('>','&gt;'))
                    diff_orig_lines.append('</font>')

                elif line.startswith(' '):
                    diff_vuln_lines.append(line[1:])
                    diff_orig_lines.append(line.replace('<','&lt;').replace('>','&gt;'))

        if diff_vuln_lines:
            diff_norm_lines = self._normalize(''.join(diff_vuln_lines), magic_ext).split()
            if len(diff_norm_lines) >= common.ngram_size:
                common.verbose_print('      %s %d (ext: %d)' % (diff_file, diff_cnt, magic_ext))
                path = '[%s] %s #%d' % (patch_filename, diff_file, diff_cnt)
                hash_list = self._build_hash_list(diff_norm_lines)
                self._patch_list.append(common.PatchInfo(path, magic_ext, ''.join(diff_orig_lines), diff_norm_lines, hash_list))
            else:
                common.verbose_print('      %s %d (ext: %d) - skipped (%d lines)' % (diff_file, diff_cnt, magic_ext, len(diff_norm_lines)))

    def _normalize(self, patch, ext):
        '''
        Normalize a patch file
        '''
        # Language-specific optimization
        if ext==common.FileExt.C or ext==common.FileExt.Java:
            patch = ''.join([c.group('noncomment') for c in common.c_regex.finditer(patch) if c.group('noncomment')])
            patch = ''.join([c.group('noncomment') for c in common.c_partial_comment_regex.finditer(patch) if c.group('noncomment')])
        elif ext==common.FileExt.ShellScript or ext==common.FileExt.Python:
            patch = ''.join([c.group('noncomment') for c in common.shellscript_regex.finditer(patch) if c.group('noncomment')])
        elif ext==common.FileExt.Perl:
            patch = ''.join([c.group('noncomment') for c in common.perl_regex.finditer(patch) if c.group('noncomment')])
        elif ext==common.FileExt.PHP:
            patch = ''.join([c.group('noncomment') for c in common.php_regex.finditer(patch) if c.group('noncomment')])
            patch = ''.join([c.group('noncomment') for c in common.c_partial_comment_regex.finditer(patch) if c.group('noncomment')])
        elif ext==common.FileExt.Ruby:
            patch = ''.join([c.group('noncomment') for c in common.ruby_regex.finditer(patch) if c.group('noncomment')])
            patch = ''.join([c.group('noncomment') for c in common.ruby_partial_comment_regex.finditer(patch) if c.group('noncomment')])

        # Remove whitespaces except newlines
        patch = common.whitespaces_regex.sub("", patch)
        # Convert into lowercases
        return patch.lower()

    def _build_hash_list(self, diff_norm_lines):
        '''
        Build a hash list
        '''
        hash_list = []
        num_ngram = len(diff_norm_lines) - common.ngram_size + 1
        for i in range(0, num_ngram):
            ngram = ''.join(diff_norm_lines[i:i+common.ngram_size])
            hash1 = common.fnv1a_hash(ngram) & (common.bloomfilter_size-1)
            hash2 = common.djb2_hash(ngram) & (common.bloomfilter_size-1)
            hash3 = common.sdbm_hash(ngram) & (common.bloomfilter_size-1)
            hash_list.append(hash1)
            hash_list.append(hash2)
            hash_list.append(hash3)
        return hash_list

    def _get_file_type(self, file_path):
        '''
        Guess a file type based upon a file extension (mimetypes module)
        '''
        file_type, encoding = mimetypes.guess_type(file_path)
        magic_ext = None
        if file_type is None:
            magic_ext = common.FileExt.Text
        else:
            main_type, sub_type = file_type.split('/')
            if sub_type.startswith('x-c'):
                magic_ext = common.FileExt.C
            elif sub_type == 'x-java':
                magic_ext = common.FileExt.Java
            elif sub_type == 'x-sh':
                magic_ext = common.FileExt.ShellScript
            elif sub_type == 'x-perl':
                magic_ext = common.FileExt.Perl
            elif sub_type == 'x-python':
                magic_ext = common.FileExt.Python
            elif sub_type == 'x-httpd-php':
                magic_ext = common.FileExt.PHP
            elif sub_type == 'x-ruby':
                magic_ext = common.FileExt.Ruby
            else:
                magic_ext = common.FileExt.Text
        return magic_ext

    def items(self):
        return self._patch_list

    def length(self):
        return self._npatch

