#!/usr/bin/env python3

import os
import shutil
from pathlib import Path
import command
import sys

sys.path.append("..")
from encbackup import enc_sync

SRC_DIR = 'src_dir'
CMP_DIR = 'cmp_dir' # for easy check of errors
BACKUP_DIR = 'backup_dir'

def clean():
    # src_dir
    shutil.rmtree(SRC_DIR, ignore_errors=True)
    shutil.rmtree(BACKUP_DIR, ignore_errors=True)
    shutil.rmtree(CMP_DIR, ignore_errors=True)
    shutil.rmtree("tmp", ignore_errors=True)

def create_files():
    Path(SRC_DIR).mkdir(parents=True, exist_ok=True)
    Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)

    with open(os.path.join(SRC_DIR, 'file01.txt'), 'w') as f: f.write('content file 01')
    with open(os.path.join(SRC_DIR, 'file02.txt'), 'w') as f: f.write('content file 02')
    with open(os.path.join(SRC_DIR, 'file03.txt'), 'w') as f: f.write('content file 03')

    Path(os.path.join(SRC_DIR, 'folder1')).mkdir(parents=True, exist_ok=True)
    with open(os.path.join(SRC_DIR, 'folder1/file04.txt'), 'w') as f: f.write('content file 04')
    with open(os.path.join(SRC_DIR, 'folder1/file05.txt'), 'w') as f: f.write('content file 05')
    with open(os.path.join(SRC_DIR, 'folder1/file06.txt'), 'w') as f: f.write('content file 06')

    Path(os.path.join(SRC_DIR, 'folder1/folder2')).mkdir(parents=True, exist_ok=True)
    with open(os.path.join(SRC_DIR, 'folder1/folder2/file07.txt'), 'w') as f: f.write('content file 07')
    with open(os.path.join(SRC_DIR, 'folder1/folder2/file08.txt'), 'w') as f: f.write('content file 08')
    with open(os.path.join(SRC_DIR, 'folder1/folder2/file09.txt'), 'w') as f: f.write('content file 09')

    Path(os.path.join(SRC_DIR, 'folder3')).mkdir(parents=True, exist_ok=True)
    with open(os.path.join(SRC_DIR, 'folder3/file10.txt'), 'w') as f: f.write('content file 10')
    with open(os.path.join(SRC_DIR, 'folder3/file11.txt'), 'w') as f: f.write('content file 11')
    with open(os.path.join(SRC_DIR, 'folder3/file12.txt'), 'w') as f: f.write('content file 12')

    save_for_compare()

def create_backup(additional_flags):
    argv = ['./../enc_sync.py', '--src=' + SRC_DIR, '--backup=' + BACKUP_DIR, '--config=test_config.ini'] + additional_flags
    enc_sync.main(argv)

def save_for_compare():
    shutil.rmtree(CMP_DIR, ignore_errors=True)
    shutil.copytree(SRC_DIR, CMP_DIR)

def compare(testname):
    res = command.run(['diff', '-qr', SRC_DIR, CMP_DIR])
    text = res.output.decode("utf-8")
    if text != "":
        print(testname + " error")
        print(text)
    else:
        print(testname + " passed")

def test_delete():
    create_backup([])

    # modify
    os.remove(os.path.join(SRC_DIR, 'file01.txt'))
    os.remove(os.path.join(SRC_DIR, 'folder1/file04.txt'))
    os.remove(os.path.join(SRC_DIR, 'folder1/folder2/file07.txt'))
    os.remove(os.path.join(SRC_DIR, 'folder3/file10.txt'))

    save_for_compare()

    # test
    create_backup(['--delete'])
    create_backup(['--restore'])

    compare("test_delete")

def test_restore():
    create_backup([])

    # modify
    os.remove(os.path.join(SRC_DIR, 'file01.txt'))
    os.remove(os.path.join(SRC_DIR, 'folder1/file04.txt'))
    os.remove(os.path.join(SRC_DIR, 'folder1/folder2/file07.txt'))
    os.remove(os.path.join(SRC_DIR, 'folder3/file10.txt'))

    create_backup(['--restore'])

    compare("test_restore")

def test_manipulate_delete_restore():
    create_backup([])

    # manipulate
    with open(os.path.join(SRC_DIR, 'file01.txt'), 'a') as f: f.write('manipulation')
    with open(os.path.join(SRC_DIR, 'folder1/file04.txt'), 'a') as f: f.write('manipulation')
    with open(os.path.join(SRC_DIR, 'folder1/folder2/file07.txt'), 'a') as f: f.write('manipulation')
    with open(os.path.join(SRC_DIR, 'folder3/file10.txt'), 'a') as f: f.write('manipulation')

    save_for_compare()
    create_backup([])

    # modify
    os.remove(os.path.join(SRC_DIR, 'file01.txt'))
    os.remove(os.path.join(SRC_DIR, 'folder1/file04.txt'))
    os.remove(os.path.join(SRC_DIR, 'folder1/folder2/file07.txt'))
    os.remove(os.path.join(SRC_DIR, 'folder3/file10.txt'))

    create_backup(['--restore'])
    compare("test_manipulate_delete_restore")

##############################################
## START OF PROGRAMM ##
##############################################
clean()
create_files()
test_delete()

clean()
create_files()
test_restore()

clean()
create_files()
test_manipulate_delete_restore()

clean()