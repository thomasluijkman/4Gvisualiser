import sys
import os
import shutil
from ltevisualiser import visualiser
import pyshark
from analyser import analysis

from packet import *


def control():
    options, parse_options = parse_arguments()
    path = sys.argv[len(sys.argv) - 1]
    cap = parse_pcap(path, parse_options)
    if options['analyse']:
        if options['sim']:
            ue_info = {}
            ue_info['sim_info'] = load_user_db(options['sim'])
            lte_analyser = analysis.Analyser(cap, list_categories(cap), ue_info)
        else:
            lte_analyser = analysis.Analyser(cap, list_categories(cap))
        lte_analyser.analyse()
    if options['visualise']:
        img = visualiser.Visualiser(cap)
        img.visualise()
    else:
        print_analysis(cap)

def config(path=""):
    """Configures a Wireshark profile such that 4G/LTE packets can be read correctly."""

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


def load_user_db(filename):
    """Loads a user_db.csv file according to srsRAN standards, and returns these values in a dictionary."""
    sim_info = None
    with open(filename, 'r') as f:
        lines = f.readlines()
    for line in lines:
        if '#' not in line:
            try:
                data = line.split(',')[1:]
                sim_info = {
                    'auth'      : data[0],
                    'imsi'      : data[1],
                    'key'       : bytes.fromhex(data[2]),
                    data[3]     : data[4],
                    'amf'       : bytes.fromhex(data[5]),
                    'sqn'       : data[6],
                    'qci'       : data[7],
                    'ip_alloc'  : data[8]
                }
            except Exception:
                raise IndexError('Something went wrong reading the file. Make sure you entered the correct filename.')
            break
    return sim_info


def parse_arguments():
    """Parses command line arguments."""
    options = {'analyse': True, 'visualise': True, 'sim': None}
    parse_options = {'-C': '4GLTE'}
    i = 1
    while i < len(sys.argv):
        if sys.argv[i][0] != '-':
            i += 1
            continue
        if sys.argv[i] == '-analyse' or sys.argv[i] == '-a':
            options['visualise'] = False
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
        if (sys.argv[i] == '-sim' or sys.argv[i] == '-s') and i + 1 < len(sys.argv):
            if sys.argv[i+1][0] != '-' and sys.argv[i+1].endswith('.csv'):
                options['sim'] = sys.argv[i+1]
            else:
                print('WARNING: SIM option is set, but no user_db file is provided.')
                print('Program will not load user_db file.')
        if sys.argv[i] == '-visualise' or sys.argv[i] == '-v':
            options['analyse'] = False
        if sys.argv[i] == '-help' or sys.argv[i] == '-h':
            print("""
            4G visualisation and analysis tool
            
            Default usage: python3 ELVis.py [OPTIONS] [filename]
            The filename must be a .pcap file.
            
            OPTIONS:
            -analyse
            Only analyse the .pcap file, without showing the UI.
            Analysis results will be shown in the terminal from which
            this program is run.
            
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
            
            -sim <file>
            If you are using srsRAN, use this command to load the user_db.csv
            in which you are using to connect to the network. Only the first
            entry will be parsed, so make sure that this is the entry you used to
            generate the .pcap files.
            
            -visualise
            Only show the UI, without performing packet analysis.
            """)
            quit()
        i += 1
    return options, parse_options


def print_analysis(data):
    for packet in data:
        if packet.eval != 0 and 'Analysed' in packet.category:
            packet_id = packet.full_summary.split()[0]
            print(f'Packet summary: {packet.full_summary}')
            print(f'------------ANALYSIS RESULTS FOR PACKET {packet_id} START------------')
            print(packet.analysis.rstrip('\n'))
            print(f'------------ANALYSIS RESULTS FOR PACKET {packet_id} STOP------------')
            print('')


def list_categories(data):
    categories = []
    for packet in data:
        for category in packet.category:
            if category not in categories:
                categories.append(category)
    return categories


def parse_pcap(path, options):
    """Parses .pcap data using PyShark library."""
    pyshark.FileCapture.SUMMARIES_BATCH_SIZE = 4
    raw_capture = pyshark.FileCapture(path, custom_parameters=options)
    summaries = pyshark.FileCapture(path, custom_parameters=options, only_summaries=True)
    assert len(raw_capture) == len(summaries)
    capture = []
    for packet, summary in zip(raw_capture, summaries):
        if len(packet.layers) > 2 and vars(packet.layers[2])['_layer_name'] == 'mac-lte':
            vars(packet.layers[2])['_layer_name'] = 'mac_lte'
        sentence = summary.summary_line
        capture.append(Packet(packet, sentence, 0))
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
