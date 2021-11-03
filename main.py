import sys
import os
import shutil
from pprint import pprint

import pyshark

from packet import *


def control():
    path = sys.argv[1]
    parse_pcap(path)


def config(path="~/.config/wireshark"):
    directory = os.path.dirname(path)
    if not os.path.exists(directory):
        print('The directory \"' + path + '\" does not exist. Please make sure the directory is correct and try again.')
        quit()
    path += '/profiles/4GLTE'
    os.makedirs(path, exist_ok=True)
    config_files = os.listdir('profile')
    for file in config_files:
        copy_path = 'profile/' + file
        print('Copying ' + copy_path + ' to ' + path + '...')
        shutil.copy(copy_path, path)


def parse_arguments():
    """Parses command line arguments."""
    i = 1
    while i < len(sys.argv):
        if sys.argv[i][0] != '-':
            i += 1
            continue
        if sys.argv[i] == '-config' or sys.argv[i] == '-c':
            print("Configuring Wireshark.")
            if i + 1 < len(sys.argv) and sys.argv[i+1][0] != '-':
                config(sys.argv[i+1])
            else:
                config()
            print("Configuration complete.")
            quit()
        if sys.argv[i] == '-help' or sys.argv[i] == '-h':
            print("""
            4G visualisation and analysis tool
            
            Default usage: python3 main.py [OPTIONS] [filename]
            The filename must be a .pcap file.
            
            OPTIONS:
            -config [directory]
            Configures Wireshark and tshark correctly for 4G packet analysis.
            The directory provided is the configuration directory for Wireshark.
            By default, this directory is "~/.config/wireshark".
            
            -help
            Displays this help message.
            """)
            quit()


def parse_pcap(path):
    """Parses .pcap data using PyShark library."""
    capture = pyshark.FileCapture(path, custom_parameters=['-C', '4GLTE'])
    print(capture[0])


if __name__ == '__main__':
    control()
