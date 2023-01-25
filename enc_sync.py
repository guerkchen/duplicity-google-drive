#!/usr/bin/env python3

import command
import subprocess
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
from cryptography.fernet import Fernet

@dataclass
class File_Entry(JSONListWizard, JSONFileWizard):
    size: int
    ctime: float
    filename: str
    enc_filename: str

def get_file_entry(filename):
    # get additional informations for every file
    size = os.path.getsize(filename) # size
    ctime = os.path.getctime(filename) # last modified date
    enc_filename = 'enc' + str(hash(filename)) + '.gpg' # create enc filename (by hashing)
    return File_Entry(size, ctime, filename, enc_filename)


def get_folder_struc(path):
    # get file list
    res = command.run(['find', path, '-type', 'f'])
    file_list = res.output.decode("utf-8")

    # create nice Container with beautiful File_Entry dataclasses
    folder_struc = Container[File_Entry]()
    for filename in file_list.split("\n"):
        folder_struc.append(get_file_entry(filename))

    return folder_struc

# expects a 2D array with rows containing: [size, ctime, file, enc_filename]
def write_masterfile(path, folder_struc, password_file):
    text = folder_struc.to_json()
    command = ['gpg', '--symmetric', '--armor', '--batch', '--yes', '--passphrase-file', password_file, '-o', path]
    out = subprocess.check_output(command, input=text.encode('utf-8'))

def read_masterfile(path, password_file):
    res = command.run(['gpg', '--batch', '--quiet', '--passphrase-file', password_file, '-d', path])
    text = res.output.decode("utf-8")
    list = File_Entry.from_json(text)

    folder_struc = Container[File_Entry]()
    for entry in list:
        folder_struc.append(entry)
    return folder_struc

def encrypt_and_backup(src_file, backup_file, password_file):
    command.run(['gpg', '--passphrase-file', password_file, '--batch', '-o', backup_file, '-c', src_file])

def decrypt_and_restore(src_file, backup_file, password_file):
    command.run(['gpg', '--passphrase-file', password_file, '--batch', '-o', src_file, '-d', backup_file])

# it would be much more elegant to store the backup struct as dictionary in the file
# but I don't want to implmenent this right now
def convert_into_dictionary(folder_struc):
    folder_dictionary = {}
    for file_entry in folder_struc:
        folder_dictionary[file_entry.filename] = file_entry # I hope, this is a pointer, so when I change the size or ctime, it is updated in the folder_struc
    return folder_dictionary

## START OF PROGRAMM ##
src_folder = ""
backup_folder = ""
password_file = ""
delete = False
restore = False

# parameter parsing
opts, args = getopt.getopt(sys.argv[1:], "dr", ["delete","restore","src=","backup=", "password="])
for opt, arg in opts:
      if opt in ('-d', '--delete'):
          delete = True
      if opt in ('-r', '--restore'):
          restore = True
      elif opt == "--src":
         src_folder = arg
      elif opt == "--backup":
         backup_folder = arg
      elif opt == "--password":
         password_file = arg

# how to use it
if src_folder == "" or backup_folder == "" or password_file == "":
    print("parameters:")
    print("--src=<src folder> [REQ]")
    print("--backup=<backup folder> [REQ]")
    print("--password=<password file> [REQ]")
    print("-d or --delete -> enables the delete process of old backup files [OPT]")
    print("-r or --restore -> recovers old backup files [OPT]")
    exit()

if delete:
    print("delete is enabled. Files which are no longer found in the src dir will be deleted in the backup dir")

if restore:
    print("restore is enabled. Files which are no longer found in the src dir will be restored in the backup dir")

## READ & PREPARE STUFF ##

# read encryption password
with open(password_file, 'r') as f:
    password = f.read()

# read existing masterfile
backup_master_filename = backup_folder + "/backup_master.gpg"
backup_file_folder = backup_folder + "/"
if os.path.isfile(backup_master_filename):
    backup_struct = read_masterfile(backup_master_filename, password_file)
else:
    if click.confirm('No backup found, create a new one?', default=True):
        Path(backup_folder).mkdir(parents=True, exist_ok=True)
        # just creat an empty container, so the programm thinks no files are backuped yet
        backup_struct = Container[File_Entry]()
    else:
        exit()

# read existing src folder struct
src_struct = get_folder_struc(src_folder)

## DO THE BACKUP ##
new_files_counter = 0
changed_files_counter = 0
neutral_files_counter = 0
removed_files_counter = 0

backup_dict = convert_into_dictionary(backup_struct)
# compare src_struct and backup_struct
for src_entry in src_struct:
    if src_entry.filename not in backup_dict:
        # file is not backuped yet
        print("new file '" + src_entry.filename + "' (" + str(src_entry.size) + ") -> encrypt & backup")
        new_files_counter += 1

        encrypt_and_backup(src_entry.filename, backup_file_folder + src_entry.enc_filename, password_file)
        backup_struct.append(src_entry) # we append the src_entry to the backup_struct. Later backup_struct is written to the masterfile.
        continue # file is handled

    # we can now assume that a backup entry for this file exists
    backup_entry = backup_dict[src_entry.filename]
    if src_entry.ctime != backup_entry.ctime or src_entry.size != backup_entry.size:
        # file content has been changed
        print("change in file '" + src_entry.filename + "' (" + str(src_entry.size) + ") -> encrypt & backup")
        changed_files_counter += 1

        encrypt_and_backup(src_entry.filename, backup_file_folder + src_entry.enc_filename, password_file)
        backup_entry.ctime = src_entry.ctime # I hope, backup_entry is a pointer to the original entry in backup_struct
        backup_entry.size = src_entry.size # I hope, backup_entry is a pointer to the original entry in backup_struct
        continue # file is handled

    print("unchanged file '" + src_entry.filename + "' (" + str(src_entry.size) + ") -> relax")
    neutral_files_counter += 1

## HANDLE REMOVED FILES ##
if delete or restore:
    # here we build the opposite loop to above
    src_dict = convert_into_dictionary(src_struct)
    for backup_entry in backup_struct:
        if backup_entry.filename not in src_dict:
            # file is no longer existence in the src
            removed_files_counter += 1
            if restore:
                # lets bring it back
                print("found lost file '" + backup_entry.filename + "' (" + str(backup_entry.size) + ") -> decrypt & restore")
                decrypt_and_restore(backup_entry.filename, backup_file_folder + backup_entry.enc_filename, password_file)
                # we dont need to restore data in the src_struct, since it will not be saved anywhere.
                # but we are required to update the ctime in the backup_struct, otherwise this file will be backuped next time, eventhough it's not necessary
                # size should not be changed
                file_entry = get_file_entry(backup_entry.filename)
                backup_dict[backup_entry.filename].ctime = file_entry.ctime

                continue # my job here is done

            if delete:
                # delete the backup file
                print("found old file '" + backup_file_folder + backup_entry.filename + "' -> delete backup file")
                #command.run(['rm', backup_entry.filename])
                backup_struct.remove(backup_entry) # since the encrypted file is deleted, the backup_entry must be deleted, too.

                continue # my job here is short and done
else:
    # there is a shortcut to compute the amount of deleted files
    removed_files_counter = len(backup_struct) - len(src_struct)

## CLEANUP ##
# save updated backup struct
write_masterfile(backup_master_filename, backup_struct, password_file)

# report
print("new files backuped: " + str(new_files_counter))
print("changed files backuped: " + str(changed_files_counter))
print("unchanged files: " + str(neutral_files_counter))
print("removed files: " + str(removed_files_counter))
print("backuped file count: " + str(len(backup_struct)))
