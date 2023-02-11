#!/usr/bin/env python3

##############################################
## IMPORTS ##
##############################################

import command
import subprocess
import os
import os.path
import shutil
import sys, getopt
import time
from hashlib import sha256
from dataclasses import dataclass
from dataclass_wizard import Container, JSONListWizard, JSONFileWizard
import click
from pathlib import Path
import logging
import configparser

##############################################
## GLOBAL VARIABLES ##
##############################################

# DEFAULT CONFIG (can be changed by config file)
MASTERFILE_WRITE_TIME_SEC = 120
MASTERFILE_NAME = "backup_master.gpg"
LOG_LEVEL = logging.INFO
TMP_PATH = "/tmp/ebfbf"

# Runtime parameters (these can be changed by command line arguments or config file)
src_dir = ""
backup_dir = ""
password_path = ""
config_path = ""
delete = False
restore = False

# this shit is required to read the debug level from the logfile
log_level_info = {
    'ALL': 0,
    'DEBUG': logging.DEBUG, 
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    }

##############################################
## CUSTOM CLASSES ##
##############################################

@dataclass
class File_Entry(JSONListWizard, JSONFileWizard):
    size: int
    ctime: float
    rel_path: str
    enc_filename: str
    enc_size: int # with this size we can assure, that the backup files are not corrupted. We can use this number to check every run that all files are valid

##############################################
## FILE ENTRY METHODS ##
##############################################

def get_folder_struc(src_dir, backup_dir):
    # get file list
    backup_scan = os.scandir(backup_dir)
    # I try to reduce the system calls to increase performance.
    # Especially the remote file systems tends to take a long time handling calls, so I ask as much as possible in one block
    # In the backup folder there is no folder structure, so one request gives all the answers

    # to reduce request time, the backup_scan is parsed into an dictionary
    backup_dict = {}
    for backup_item in backup_scan:
        backup_dict[backup_item.name] = backup_item.stat().st_size

    # I am really worried by some stupid mistake I'm goint to delete my backup_master.gpg
    # to prevent this, I remove it from the "real" backup_dict completely
    if MASTERFILE_NAME in backup_dict:
        del backup_dict[MASTERFILE_NAME]

    return get_folder_struc_rec(src_dir, backup_dict, src_dir), backup_dict

# Hopefully there will be a method to scandirs recursive soon
# os.walk is not useful since it doesn't deliver the files size and ctime
def get_folder_struc_rec(rec_scan, backup_dict, src_dir):
    for file in os.scandir(rec_scan):
        if file.name.startswith('.'):
            # skip hidden files
            # we check this before we handle folders, so hidden folders will be skipped aswell
            yield
            continue

        abs_path = file.path
        if file.is_dir():
            # go deeper on folders
            yield from get_folder_struc_rec(abs_path, backup_dict, src_dir)
            continue

        if file.is_file():
            # at this point, we found a file
            rel_path = os.path.relpath(abs_path, src_dir)
            enc_filename = 'enc-' + sha256(rel_path.encode('utf-8')).hexdigest() + '.gpg' # create enc filename (by hashing)
            if enc_filename not in backup_dict:
                # no backup file found. This normally happens, when the file is not backuped yet
                # but it could also mean, that we lost the backuped file or it is corrupted.
                # to notify this cases, the file size is used
                enc_size = 0
            else:
                enc_size = backup_dict[enc_filename]
                del backup_dict[enc_filename] # by deleting the entry at this point, we can use the remaining entries later to determine lost+found files in the backup directory

            yield File_Entry(file.stat().st_size, file.stat().st_ctime, rel_path, enc_filename, enc_size)
            continue

##############################################
## MASTERFILE READ AND WRITE ##
##############################################

# we do a little Choreography to garantee, there is always a valid backup_master file available
def write_masterfile(masterfile_abs_path, masterfile_abs_path_old, folder_struc, password_path):
    logging.debug("save masterfile to backup drive")

    tmp_file = os.path.join(TMP_PATH, MASTERFILE_NAME)
    text = folder_struc.to_json()

    # write the encrypted masterfile to the tmp folder
    logging.log(5, "encrypt masterfile")
    command = ['gpg', '--symmetric', '--armor', '--batch', '--yes', '--passphrase-file', password_path, '-o', tmp_file]
    out = subprocess.check_output(command, input=text.encode('utf-8'))

    if os.path.isfile(masterfile_abs_path):
        # rename the current masterfile on the backup drive (if it exists)
        logging.log(5, "backup old masterfile")
        os.rename(masterfile_abs_path, masterfile_abs_path_old)

    logging.log(5, "transfer new masterfile to backup drive")
    os.rename(tmp_file, masterfile_abs_path)

    if os.path.isfile(masterfile_abs_path_old):
        logging.log(5, "delete the old masterfile")
        os.remove(masterfile_abs_path_old)


# I want to implement a routine, which uses the old masterfile, if the current one is broken
def read_masterfile(masterfile_abs_path, masterfile_abs_path_old, password_path):
    logging.debug("read masterfile from backup drive")
    res = command.run(['gpg', '--batch', '--quiet', '--passphrase-file', password_path, '-d', masterfile_abs_path])
    text = res.output.decode("utf-8")
    list = File_Entry.from_json(text)

    folder_struc = Container[File_Entry]()
    for entry in list:
        folder_struc.append(entry)

    return folder_struc

##############################################
## BACKUP AND RESTORE ##
##############################################

def encrypt_and_backup(src_rel_path, src_dir, backup_dir, enc_filename, password_path):
    # the backup file is created on the local machine and copied to the backup location later, this is significant faster
    tmp_abs_path = os.path.join(TMP_PATH, enc_filename)
    src_abs_path = os.path.join(src_dir, src_rel_path)
    backup_abs_path = os.path.join(backup_dir, enc_filename)

    logging.log(5, "encrypt '" + src_rel_path + "'")
    command.run(['gpg', '--passphrase-file', password_path, '--batch', '-o', tmp_abs_path, '-c', src_abs_path])

    logging.log(5, "backup '" + enc_filename + "'")
    command.run(['mv', tmp_abs_path, backup_abs_path])

    enc_size = os.path.getsize(backup_abs_path)
    logging.log(5, "backup finished (" + str(enc_size) + " bytes)")
    return enc_size


def decrypt_and_restore(src_rel_path, src_dir, backup_folder, backup_filename, password_path):
    # the backup file is copied on the local machine, where it is decrypted, this is significant faster
    tmp_abs_path = os.path.join(TMP_PATH, backup_filename)
    src_abs_path = os.path.join(src_dir, src_rel_path)
    backup_abs_path = os.path.join(backup_folder, backup_filename)

    logging.log(5, "bring back '" + backup_filename + "'")
    command.run(['cp', backup_abs_path, tmp_abs_path])

    logging.log(5, "decrypt '" + src_rel_path + "'")
    Path(os.path.dirname(src_abs_path)).mkdir(parents=True, exist_ok=True) # if the parent directory doesn't exist, it must be created first
    command.run(['gpg', '--passphrase-file', password_path, '--batch', '-o', src_abs_path, '-d', tmp_abs_path])
    command.run(['rm', tmp_abs_path])

###############################################

# it would be much more elegant to store the backup struct as dictionary in the masterfile
# but I don't want to implmenent this right now
def convert_into_dictionary(folder_struc):
    folder_dictionary = {}
    for file_entry in folder_struc:
        folder_dictionary[file_entry.rel_path] = file_entry # I hope, this is a pointer, so when I change the size or ctime, it is updated in the folder_struc
    return folder_dictionary

###############################################
###############################################
#####  START OF MAIN PROGRAMM  #####
###############################################
###############################################

def main(argv):
    # DEFAULT CONFIG (can be changed by config file)
    global MASTERFILE_WRITE_TIME_SEC, MASTERFILE_NAME, LOG_LEVEL, TMP_PATH
    global src_dir, backup_dir, password_path, config_path, delete, restore

    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=0,
        datefmt='%Y-%m-%d %H:%M:%S')

    # parameter parsing
    opts, args = getopt.getopt(argv[1:], 'dr', ['delete','restore','src=','backup=', 'password=', 'config='])

    # we parse for the config file first, so we can read it before we read the other cmd line arguments
    # this way parameters from the config file can be overwritten by cmd line arguments
    for opt, arg in opts:
        if opt == "--config":
            config_path = arg

    if config_path == "":
        logging.info("no config file specified, search for './config.ini'")
        config_path = './config.ini'

    if os.path.isfile(config_path):
        # parse config
        config = configparser.ConfigParser()

        config.read(config_path)

        # read config values
        MASTERFILE_WRITE_TIME_SEC = config.getint('CONSTANT', 'MASTERFILE_WRITE_TIME_SEC', fallback=MASTERFILE_WRITE_TIME_SEC)
        MASTERFILE_NAME = config.get('CONSTANT', 'MASTERFILE_NAME', fallback=MASTERFILE_NAME)
        LOG_LEVEL = log_level_info.get(config.get('CONSTANT', 'LOG_LEVEL', fallback=logging.ERROR), logging.ERROR)
        TMP_PATH = config.get('CONSTANT', 'TMP_PATH', fallback=TMP_PATH)

        src_dir = config.get('VARIABLE', 'SRC_DIR', fallback=src_dir)
        backup_dir = config.get('VARIABLE', 'BACKUP_DIR', fallback=backup_dir)
        password_path = config.get('VARIABLE', 'PASSWORD_PATH', fallback=password_path)
        delete = config.getboolean('VARIABLE', 'DELETE', fallback=delete)
        restore = config.getboolean('VARIABLE', 'RESTORE', fallback=restore)

    elif os.path.normpath(config_path) != os.path.normpath('config.ini'):
        # if a config file is specified, it must be found, only the default config file can be missed
        sys.exit("configfile '" + config_path + "' not found")

    # now read the other cmd line arguments and maybe overwrite some values
    for opt, arg in opts:
        if opt in ('-d', '--delete'):
            delete = True
        if opt in ('-r', '--restore'):
            restore = True
        elif opt == "--src":
            src_dir = arg
        elif opt == "--backup":
            backup_dir = arg
        elif opt == "--password":
            password_path = arg

    # some variables must be filled, either from the config file or the cmd line argument
    if src_dir == "" or backup_dir == "" or password_path == "":
        logging.error("parameters:")
        logging.error("--src=<src directory> [REQ]")
        logging.error("--backup=<backup directory> [REQ]")
        logging.error("--password=<password path> [REQ]")
        logging.error("--config=<config path> [OPT] config file parameters are overwritten by cmd line arguments")
        logging.error("-d or --delete -> enables the delete process of old backup files [OPT]")
        logging.error("-r or --restore -> recovers old backup files [OPT]")
        raise SystemExit("missing parameters")

    if delete & restore:
        sys,exit("cannot set parameter delete and restore, only one is allowed")

    if delete:
        logging.info("delete is enabled. Files which are no longer found in the src dir will be deleted in the backup dir")

    if restore:
        logging.info("restore is enabled. Files which are no longer found in the src dir will be restored in the backup dir")


    ###############################################
    ## READ & PREPARE STUFF ##
    ###############################################

    # adjust loglevel
    logging.getLogger().setLevel(LOG_LEVEL)

    # read encryption password
    with open(password_path, 'r') as f:
        password = f.read()

    # create and emptry tmp file
    shutil.rmtree(TMP_PATH, ignore_errors=True)
    Path(TMP_PATH).mkdir(parents=True, exist_ok=True)

    # read existing masterfile
    masterfile_abs_path = os.path.join(backup_dir, MASTERFILE_NAME)
    masterfile_abs_path_old = masterfile_abs_path + ".old"
    if os.path.isfile(masterfile_abs_path):
        should_struct = read_masterfile(masterfile_abs_path, masterfile_abs_path_old, password_path)
    else:
        # master_backup.gpg not found, look for master_backup.gpg.old (backup from the last version)
        if os.path.isfile(masterfile_abs_path_old):
            # when an old version of the masterfile is found, it can be used
            if click.confirm('Masterfile not found, but an older version is available. Use it?', default=True):
                should_struct = read_masterfile(masterfile_abs_path_old, password_path)
            else:
                exit()
        else:
            if click.confirm('No ' + MASTERFILE_NAME + ' found, so I assume, there is no backup. Create a new one?', default=True):
                Path(backup_dir).mkdir(parents=True, exist_ok=True)
                # just creat an empty container, so the programm thinks no files are backuped yet
                should_struct = Container[File_Entry]()
            else:
                exit()

    # read existing src folder struct
    is_struct, lost_found_backup_dict = get_folder_struc(src_dir, backup_dir)

    ###############################################
    ## DO THE BACKUP (handle new and changed files) ##
    ###############################################
    new_files_counter = 0
    changed_files_counter = 0
    corrupt_files_counter = 0
    neutral_files_counter = 0
    removed_files_counter = 0
    lost_found_files_counter = 0

    masterfile_last_written = time.time()
    should_dict = convert_into_dictionary(should_struct)
    # compare src_struct and backup_struct
    for is_entry in is_struct:
        # every two minutes, the masterfile is encrypted and written, so when you cancel the programm during backup, not everything is lost
        if masterfile_last_written + MASTERFILE_WRITE_TIME_SEC < time.time(): # 2 minutes passed
            # write masterfile
            write_masterfile(masterfile_abs_path, masterfile_abs_path_old, should_struct, password_path)
            masterfile_last_written = time.time()

        ###############################################
        ## New File ##
        if is_entry.rel_path not in should_dict:
            # file is not backuped yet
            logging.debug("new file '" + is_entry.rel_path + "' (" + str(is_entry.size) + ") -> encrypt & backup")
            new_files_counter += 1

            is_entry.enc_size = encrypt_and_backup(is_entry.rel_path, src_dir, backup_dir, is_entry.enc_filename, password_path)
            # it's crucial that we first finish the file copy and then we update the should_struct
            # otherwise, if the program is killed during the backup process, the one backup file is corrupted and will not be fixed
            # This is not completly true, since we use the size of the encrypted file to check if it is valid, but still this way is better
            should_struct.append(is_entry) # we append the is_entry to the should_struct. Later should_struct is written to the masterfile.
            continue # file is handled
        ###############################################

        # we can now assume that a backup entry for this file exists
        # we mark the object as handled by deleting it from the should_dict. Not the should_struct(!!) which is written to the MASTERFILE later
        # when leaving this loop, the remaining entries in the should_dict are no longer existence in the src_folder, so we must decide, wether we bring them back or delete them from the backup aswell
        should_entry = should_dict.pop(is_entry.rel_path)

        ###############################################
        ## Changed File ##
        if is_entry.ctime != should_entry.ctime or is_entry.size != should_entry.size or is_entry.enc_size != should_entry.enc_size:
            if is_entry.enc_size != should_entry.enc_size:
                # enc file is corrupt
                logging.debug("corrupted file '" + is_entry.rel_path + "' (" + str(is_entry.size) + ") -> encrypt & backup")
                logging.debug(str(is_entry.enc_size) + " != " + str(should_entry.enc_size))
                corrupt_files_counter += 1
            else:
                # file content has been changed
                logging.debug("change in file '" + is_entry.rel_path + "' (" + str(is_entry.size) + ") -> encrypt & backup")
                changed_files_counter += 1

            should_entry.enc_size = encrypt_and_backup(is_entry.rel_path, src_dir, backup_dir, should_entry.enc_filename, password_path)
            should_entry.ctime = is_entry.ctime # I hope, should_entry is a pointer to the original entry in should_struct
            should_entry.size = is_entry.size # I hope, should_entry is a pointer to the original entry in should_struct
            continue # file is handled
        ###############################################

        logging.debug("unchanged file '" + is_entry.rel_path + "' (" + str(is_entry.size) + ") -> relax")
        neutral_files_counter += 1

    ###############################################
    ## HANDLE REMOVED FILES ##
    ###############################################
    # since we removed all valid entries from the should_dict, only the removed files are remaining.
    for should_entry in should_dict.values():
        # file is no longer existence in the src
        removed_files_counter += 1

        if should_entry.enc_filename in lost_found_backup_dict:
            del lost_found_backup_dict[should_entry.enc_filename]
        else:
            logging.warning("unfortunately, we lost a src_file and the corresponding backup file. '" + should_entry.rel_path + "' is lost forever")
            should_struct.remove(should_entry)

        if restore:
            # lets bring it back
            logging.debug("found lost file '" + should_entry.rel_path + "' (" + str(should_entry.size) + ") -> decrypt & restore")
            decrypt_and_restore(should_entry.rel_path, src_dir, backup_dir, should_entry.enc_filename, password_path)
            # we dont need to restore data in the src_struct, since it will not be saved anywhere.
            # but we are required to update the ctime in the backup_struct, otherwise this file will be backuped next time, eventhough it's not necessary.
            # size should not be changed
            should_abs_path = os.path.join(src_dir, should_entry.rel_path)
            should_entry.ctime = os.path.getctime(should_abs_path)

            continue # my job here is done

        if delete:
            # delete the backup file
            enc_filename = os.path.join(backup_dir, should_entry.enc_filename)
            logging.debug("found old file '" + should_entry.rel_path + "' -> delete backup file")
            os.remove(enc_filename)
            should_struct.remove(should_entry) # since the encrypted file is deleted, the backup_entry must be deleted, too.

            continue # my job here is short and done

    ###############################################
    ## HANDLE LOST+FOUND FILES ##
    ###############################################
    # in the backup folder might be some files, which are not known to this backup software
    # these files don't belong there, so they get deleted
    for lost_found_backup_entry in lost_found_backup_dict:
        lost_found_files_counter +=1

        lost_found_filename = os.path.join(backup_dir, lost_found_backup_entry)
        if os.path.isfile(lost_found_filename): # this makes the code more robust
            logging.debug("delete lost+found file '" + lost_found_backup_entry + "'")
            os.remove(lost_found_filename)
        else:
            logging.warning("want to delete '" + lost_found_backup_entry + "' but it's already gone")

    ###############################################
    ## CLEANUP ##
    ###############################################
    # save updated backup struct
    write_masterfile(masterfile_abs_path, masterfile_abs_path_old, should_struct, password_path)

    # report
    logging.info("new files backuped: " + str(new_files_counter))
    logging.info("changed files backuped: " + str(changed_files_counter))
    logging.info("corrupted files: " + str(corrupt_files_counter))
    logging.info("unchanged files: " + str(neutral_files_counter))
    logging.info("removed files: " + str(removed_files_counter))
    logging.info("lost+found files: " + str(lost_found_files_counter))
    logging.info("backuped file count: " + str(len(should_struct)))

    ###############################################
    ## END OF MAIN PROGRAMM ##
    ###############################################

if __name__ == '__main__':
    main(sys.argv)