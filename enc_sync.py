#!/usr/bin/env python3

import command
import subprocess
import os
import os.path
import sys, getopt
import time
from hashlib import sha256
from dataclasses import dataclass
from dataclass_wizard import Container, JSONListWizard, JSONFileWizard
import click
from pathlib import Path
from cryptography.fernet import Fernet
import logging

MASTERFILE_WRITE_TIME_SEC = 120

@dataclass
class File_Entry(JSONListWizard, JSONFileWizard):
    size: int
    ctime: float
    filename: str
    enc_filename: str
    enc_size: int # with this size we can assure, that the backup files are not corrupted. We can use this number to check every run that all files are valid

###############################################

def get_file_entry(filename):
    # get additional informations for every file
    size = os.path.getsize(filename) # size
    ctime = os.path.getctime(filename) # last modified date
    enc_filename = 'enc-' + sha256(filename.encode('utf-8')).hexdigest() + '.gpg' # create enc filename (by hashing)
    file_entry =  File_Entry(size, ctime, filename, enc_filename, 0)
    logging.log(1, file_entry)
    return file_entry

def get_folder_struc(src_folder, backup_folder):
    # get file list
    backup_scan = os.scandir(backup_folder)
    # I try to reduce the system calls to increase performance.
    # Especionally the remote file systems tends to take a long time handling calls, so I ask as much as possible in one block
    # In the backup folder there is no folder structure, so one request gives all the answers

    # to increase request time, the backup_scan is parsed into an dictionary
    backup_dict = {}
    for backup_item in backup_scan:
        backup_dict[backup_item.name] = backup_item.stat().st_size

    # I am really worried by some stupid mistake I'm goint to delete my backup_master.gpg
    # to prevent this, I remove it from the "real" backup_dict completely
    if "backup_master.gpg" in backup_scan:
        del backup_dict["backup_master.gpg"]

    return get_folder_struc_rec(src_folder, backup_dict), backup_dict

# Hopefully there will be a method to scandirs recursive soon
# os.walk is not useful since it doesn't deliver the files size and ctime
def get_folder_struc_rec(rec_scan, backup_dict):
    for file in os.scandir(rec_scan):
        if file.name.startswith('.'):
            # skip hidden files
            # we check this before we handle folders, so hidden folders will be skipped aswell
            continue

        filename = file.path
        if file.is_dir():
            # go deeper on folders
            yield from get_folder_struc_rec(filename, backup_folder)
            continue

        enc_filename = 'enc-' + sha256(filename.encode('utf-8')).hexdigest() + '.gpg' # create enc filename (by hashing)
        if enc_filename not in backup_dict:
            # no backup file found. This normally happens, when the file is not backuped yet
            # but it could also mean, that we lost the backuped file or it is corrupted.
            # to notify this cases, the file size is used
            enc_size = 0
        else:
            enc_size = backup_dict[enc_filename]
            del backup_dict[enc_filename] # by deleting the entry at this point, we can use the remaining entries later to determine lost+found files in the backup directory

        yield File_Entry(file.stat().st_size, file.stat().st_ctime, filename, enc_filename, enc_size)
        print("test")

###############################################

# expects a 2D array with rows containing: [size, ctime, file, enc_filename]
def write_masterfile(path, folder_struc, password_file):
    logging.debug("save masterfile to backup drive")
    text = folder_struc.to_json()
    command = ['gpg', '--symmetric', '--armor', '--batch', '--yes', '--passphrase-file', password_file, '-o', path]
    out = subprocess.check_output(command, input=text.encode('utf-8'))

def read_masterfile(path, password_file):
    logging.debug("read masterfile from backup drive")
    res = command.run(['gpg', '--batch', '--quiet', '--passphrase-file', password_file, '-d', path])
    text = res.output.decode("utf-8")
    list = File_Entry.from_json(text)

    folder_struc = Container[File_Entry]()
    for entry in list:
        folder_struc.append(entry)
    return folder_struc

###############################################

def encrypt_and_backup(src_file, backup_folder, backup_filename, password_file):
    # the backup file is created on the local machine and copied to the backup location later, this is significant faster
    tmp_file = "/tmp/" + backup_filename
    backup_file = backup_folder + backup_filename
    logging.log(5, "encrypt '" + src_entry.filename)
    command.run(['gpg', '--passphrase-file', password_file, '--batch', '-o', tmp_file, '-c', src_file])
    logging.log(5, "backup '" + backup_filename)
    command.run(['mv', tmp_file, backup_file])
    enc_size = os.path.getsize(backup_file)
    logging.log(5, "backup finished (" + str(enc_size) + " bytes)")

    return enc_size

def decrypt_and_restore(src_file, backup_folder, backup_filename, password_file):
    # the backup file is copied on the local machine, where it is decrypted, this is significant faster
    tmp_file = "/tmp/" + backup_filename
    backup_file = backup_folder + backup_filename
    logging.log(5, "bring back '" + backup_filename)
    command.run(['cp', backup_file, tmp_file])
    logging.log(5, "decrypt '" + src_entry.filename)
    command.run(['gpg', '--passphrase-file', password_file, '--batch', '-o', src_file, '-d', tmp_file])
    command.run(['rm', tmp_file])

###############################################

# it would be much more elegant to store the backup struct as dictionary in the masterfile
# but I don't want to implmenent this right now
def convert_into_dictionary(folder_struc):
    folder_dictionary = {}
    for file_entry in folder_struc:
        folder_dictionary[file_entry.filename] = file_entry # I hope, this is a pointer, so when I change the size or ctime, it is updated in the folder_struc
    return folder_dictionary

###############################################
## START OF PROGRAMM ##
###############################################
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

###############################################
## READ & PREPARE STUFF ##
###############################################

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=0,
    datefmt='%Y-%m-%d %H:%M:%S')

# read encryption password
with open(password_file, 'r') as f:
    password = f.read()

# read existing masterfile
backup_master_filename = backup_folder + "/backup_master.gpg"
backup_file_folder = backup_folder + "/"
if os.path.isfile(backup_master_filename):
    backup_struct = read_masterfile(backup_master_filename, password_file)
else:
    #if click.confirm('No backup found, create a new one?', default=True):
    Path(backup_folder).mkdir(parents=True, exist_ok=True)
    # just creat an empty container, so the programm thinks no files are backuped yet
    backup_struct = Container[File_Entry]()
    #else:
        #exit()

# read existing src folder struct
src_struct, lost_found_backup_dict = get_folder_struc(src_folder, backup_folder)
for ele in src_struct:
    print (ele)
exit()

###############################################
## DO THE BACKUP ##
###############################################
new_files_counter = 0
changed_files_counter = 0
corrupt_files_counter = 0
neutral_files_counter = 0
removed_files_counter = 0

masterfile_last_written = 0
backup_dict = convert_into_dictionary(backup_struct)
# compare src_struct and backup_struct
for src_entry in src_struct:
    # every two minutes, the masterfile is encrypted and written, so when you cancel the programm during backup, not everything is lost
    if masterfile_last_written + MASTERFILE_WRITE_TIME_SEC < time.time(): # 2 minutes passed
        # write masterfile
        write_masterfile(backup_master_filename, backup_struct, password_file)
        masterfile_last_written = time.time()

    if src_entry.filename not in backup_dict:
        # file is not backuped yet
        logging.debug("new file '" + src_entry.filename + "' (" + str(src_entry.size) + ") -> encrypt & backup")
        new_files_counter += 1

        src_entry.enc_size = encrypt_and_backup(src_entry.filename, backup_file_folder, src_entry.enc_filename, password_file)
        # it's crucial that we first finish the file copy and then we update the backup_struct
        # otherwise, if the program is killed during the backup process, the one backup file is corrupted and will not be fixed
        # This is not completly true, since we use the size of the encrypted file to check if it is valid, but still this way is better
        backup_struct.append(src_entry) # we append the src_entry to the backup_struct. Later backup_struct is written to the masterfile.
        continue # file is handled

    # we can now assume that a backup entry for this file exists
    backup_entry = backup_dict[src_entry.filename]
    if src_entry.ctime != backup_entry.ctime or src_entry.size != backup_entry.size:
        # file content has been changed
        logging.debug("change in file '" + src_entry.filename + "' (" + str(src_entry.size) + ") -> encrypt & backup")
        changed_files_counter += 1

        backup_entry.enc_size = encrypt_and_backup(src_entry.filename, backup_file_folder, backup_entry.enc_filename, password_file)
        backup_entry.ctime = src_entry.ctime # I hope, backup_entry is a pointer to the original entry in backup_struct
        backup_entry.size = src_entry.size # I hope, backup_entry is a pointer to the original entry in backup_struct
        continue # file is handled

    logging.debug("unchanged file '" + src_entry.filename + "' (" + str(src_entry.size) + ") -> relax")
    neutral_files_counter += 1

###############################################
## HANDLE REMOVED FILES ##
###############################################
if delete or restore:
    # here we build the opposite loop to above
    src_dict = convert_into_dictionary(src_struct)
    for backup_entry in backup_struct:
        if backup_entry.filename not in src_dict:
            # file is no longer existence in the src
            removed_files_counter += 1
            if restore:
                # lets bring it back
                logging.debug("found lost file '" + backup_entry.filename + "' (" + str(backup_entry.size) + ") -> decrypt & restore")
                decrypt_and_restore(backup_entry.filename, backup_file_folder, backup_entry.enc_filename, password_file)
                # we dont need to restore data in the src_struct, since it will not be saved anywhere.
                # but we are required to update the ctime in the backup_struct, otherwise this file will be backuped next time, eventhough it's not necessary
                # size should not be changed
                file_entry = get_file_entry(backup_entry.filename)
                backup_dict[backup_entry.filename].ctime = file_entry.ctime

                continue # my job here is done

            if delete:
                # delete the backup file
                logging.debug("found old file '" + backup_file_folder + backup_entry.filename + "' -> delete backup file")
                command.run(['rm', backup_entry.filename])
                backup_struct.remove(backup_entry) # since the encrypted file is deleted, the backup_entry must be deleted, too.

                continue # my job here is short and done
else:
    # there is a shortcut to compute the amount of deleted files
    removed_files_counter = len(backup_struct) - len(src_struct)

###############################################
## CLEANUP ##
###############################################
# save updated backup struct
write_masterfile(backup_master_filename, backup_struct, password_file)

# report
logging.info("new files backuped: " + str(new_files_counter))
logging.info("changed files backuped: " + str(changed_files_counter))
logging.info("corrupted files: " + str(corrupt_files_counter))
logging.info("unchanged files: " + str(neutral_files_counter))
logging.info("removed files: " + str(removed_files_counter))
logging.info("backuped file count: " + str(len(backup_struct)))
