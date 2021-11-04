import sys
import os
import shutil
from pprint import pprint

import pyshark

from packet import *


def control():
    parse_arguments()
    path = sys.argv[len(sys.argv) - 1]
    cap = parse_pcap(path)
    print(cap[0].get_data())

def config(path=""):
    print("Configuring Wireshark.")
    USER = os.getenv('USER')
    if path == "":
        path = '/home/' + USER + '/.config/wireshark'
    directory = os.path.dirname(path)
    if not os.path.exists(directory):
        print('The directory \"' + path + '\" does not exist. Please make sure the directory is correct and try again.')
        quit()
    path += '/profiles/4GLTE'
    directory = os.path.dirname(path)
    if os.path.exists(directory):
        print('Profile 4GLTE already exists. No configuration necessary.')
    os.makedirs(path, exist_ok=True)
    print('Created profile 4GLTE.')
    config_files = os.listdir('profile')
    for file in config_files:
        copy_path = 'profile/' + file
        print('Copying ' + copy_path + ' to ' + path + '...')
        shutil.copy(copy_path, path)
    print("Configuration complete.")


def parse_arguments():
    """Parses command line arguments."""
    i = 1
    while i < len(sys.argv):
        if sys.argv[i][0] != '-':
            i += 1
            continue
        if sys.argv[i] == '-config' or sys.argv[i] == '-c':
            if i + 1 < len(sys.argv) and sys.argv[i+1][0] != '-':
                config(sys.argv[i+1])
            else:
                config()
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
            By default, this directory is "/home/$USER/.config/wireshark".
            
            -help
            Displays this help message.
            """)
            quit()


def parse_pcap(path):
    """Parses .pcap data using PyShark library."""
    raw_capture = pyshark.FileCapture(path, custom_parameters=['-C', '4GLTE'])
    capture = []
    for packet in raw_capture:
        if len(packet.layers) > 2 and vars(packet.layers[2])['_layer_name'] == 'mac-lte':
            vars(packet.layers[2])['_layer_name'] = 'mac_lte'
        capture.append(Packet(packet, 0))
    if len(capture) == 0:
        print("no good")
        quit()
    return capture

if __name__ == '__main__':
    control()
