import sys
import os
import shutil
from pprint import pprint

import pyshark

from packet import *


def control():
    options, parse_options = parse_arguments()
    path = sys.argv[len(sys.argv) - 1]
    cap = parse_pcap(path, parse_options)


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
    options = {}
    parse_options = {'-C': '4GLTE'}
    i = 1
    while i < len(sys.argv):
        if sys.argv[i][0] != '-':
            i += 1
            continue
        if sys.argv[i] == '-config' or sys.argv[i] == '-c':
            if i + 1 < len(sys.argv) and sys.argv[i+1][0] != '-' and not sys.argv[i+1].endswith('.pcap'):
                config(sys.argv[i+1])
            else:
                config()
            quit()
        if (sys.argv[i] == '-filter' or sys.argv[i] == '-f') and i + 1 < len(sys.argv):
            if sys.argv[i + 1][0] != '-' and not sys.argv[i+1].endswith('.pcap'):
                parse_options['-f'] = sys.argv[i+1]
            else:
                print('WARNING: Filter option is set, but no filter string is provided.')
                print('Program will be run without filter.')
        if (sys.argv[i] == '-limit' or sys.argv[i] == '-l') and i + 1 < len(sys.argv):
            if sys.argv[i+1][0] != '-' and not sys.argv[i+1].endswith('.pcap'):
                parse_options['-c'] = sys.argv[i+1]
            else:
                print('WARNING: Limit option is set, but no limit count is provided.')
                print('Program will be run without capture limit.')
        if (sys.argv[i] == '-profile' or sys.argv[i] == '-p') and i + 1 < len(sys.argv):
            if sys.argv[i+1][0] != '-' and not sys.argv[i+1].endswith('.pcap'):
                parse_options['-C'] = sys.argv[i+1]
            else:
                print('WARNING: Profile option is set, but no profile is provided.')
                print('Program will be run with default profile name (4GLTE).')
        if sys.argv[i] == '-help' or sys.argv[i] == '-h':
            print("""
            4G visualisation and analysis tool
            
            Default usage: python3 main.py [OPTIONS] [filename]
            The filename must be a .pcap file.
            
            OPTIONS:
            -config <directory>
            Configures Wireshark and tshark correctly for 4G packet analysis.
            The directory provided is the configuration directory for Wireshark.
            By default, this directory is "/home/$USER/.config/wireshark".
            
            -filter <capture filter>
            Filters the packets loaded into the program.
            For information on how to format a capture filter, 
            check the tshark documentation.
            
            -help
            Displays this help message.
            
            -limit <number of packets>
            Limits the number of packets loaded into the program.
            Recommended for larger packet captures.
            
            -profile <profile name>
            If you already have a profile that correctly captures LTE traffic,
            you can use this command to use that profile instead.
            However, since settings might be different, the program might
            not work correctly, and thus it is recommended to use -config
            and work with the default configuration instead.
            """)
            quit()
        i += 1
    return options, parse_options


def parse_pcap(path, options):
    """Parses .pcap data using PyShark library."""
    raw_capture = pyshark.FileCapture(path, custom_parameters=options)
    capture = []
    for packet in raw_capture:
        if len(packet.layers) > 2 and vars(packet.layers[2])['_layer_name'] == 'mac-lte':
            vars(packet.layers[2])['_layer_name'] = 'mac_lte'
        capture.append(Packet(packet, 0))
    if len(capture) == 0:
        print("""
        No captures were loaded into the program.
        This can either be caused by an erroneous file name or a configuration error.
        Check if you got the correct file name and if the configuration is correct.
        """)
        quit()
    else:
        print('Loaded ' + str(len(capture)) + ' packets.')
    return capture


if __name__ == '__main__':
    control()
