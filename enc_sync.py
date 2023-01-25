#!/usr/bin/env python3

import command
import os
import os.path
import sys, getopt
import datetime
import pprint
from dataclasses import dataclass
from dataclass_wizard import Container, JSONListWizard, JSONFileWizard
import json
import click
from pathlib import Path

@dataclass(frozen=True)
class Backup_file(JSONListWizard, JSONFileWizard):
    size: int
    ctime: float
    filename: str
    enc_filename: str

def get_folder_struc(path):
    # get file list
    res = command.run(['find', path, '-type', 'f'])
    file_list = res.output.decode("utf-8")

    # get additional informations for every file
    folder_struc = Container[Backup_file]()
    for filename in file_list.split("\n"):
        size = os.path.getsize(filename) # size
        ctime = os.path.getctime(filename) # last modified date
        enc_filename = "enc" + str(hash(filename)) # create enc filename (by hashing)
        tmp = Backup_file(size, ctime, filename, enc_filename)
        folder_struc.append(tmp)

    return folder_struc

# expects a 2D array with rows containing: [size, ctime, file, enc_filename]
def write_masterfile(path, folder_struc):
    folder_struc.to_json_file(path, indent=4)

def read_masterfile(path):
    return Backup_file.from_json_file(path)

## START OF PROGRAMM ##
src_folder = ""
backup_folder = ""
delete = False
silent = False

opts, args = getopt.getopt(sys.argv[1:], "ds", ["delete","src=","backup="])
for opt, arg in opts:
      if opt in ('-d', '--delete'):
          delete = True
      if opt = '-s':
          silent = True
      elif opt in ("-s", "--src"):
         src_folder = arg
      elif opt in ("-b", "--backup"):
         backup_folder = arg

if src_folder == "" or backup_folder == "":
    print("parameters:")
    print("--src=<src folder> [REQ]")
    print("--backup=<backup folder> [REQ]")
    print("-s -> full backup (including the delete flag) without any questions")
    print("-d or --delete -> enables the delete process of old backup files [OPT]")
    exit()

if not delete and not silent:
    print("delete is not enabled. Files which are no longer found in the src dir will stay in the backup dir")

if silent:
    print("i will do my job and not ask any futher questions")

backup_master_filename = backup_folder + "/backup_master.json"

# read existing masterfile
if os.path.isfile(backup_master_filename):
    backup_struct = read_masterfile(backup_master_filename)
else:
    if silent or lick.confirm('No backup found, create a new one?', default=True):
        Path(backup_folder).mkdir(parents=True, exist_ok=True)
        # just creata an empty container, so the programm thinks no files are backuped yet
        backup_struct = Container[Backup_file]()
    else:
        exit()

# read existing src folder struct
src_struct = get_folder_struc(src_folder)

# compare src_struct and backup_struct (O(n²), but I don't care currently)
