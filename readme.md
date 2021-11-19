#E-UTRAN LTE Visualiser (ELVis)
The E-UTRAN LTE Visualiser (abbreviated: ELVis) is a tool that allows 
the user to analyse their LTE packet captures with ease. The aim of 
this tool is to allow more accessibility to 4G/LTE network traffic 
analysis. ELVis parses data using TShark, however no prior 4G/LTE 
configuration needs to be performed.

## Getting started
**Note: ELVis has been developed for Ubuntu 20.04. It might work on
different Linux setups, however, no tests have been performed here.**

First of all, ELVis does not generate `.pcap` files. The user is expected
to provide packet captures themselves. Applications like srsRAN can be
used for this purpose.

ELVis is a pure Python program. All of the official Python libraries
can be installed with the following command:

```sudo apt install python3 python3-tk```

ELVis also uses Pyshark, a TShark wrapper tool 
(https://github.com/KimiNewt/pyshark). Pyshark can be installed
using Pip:

```pip install pyshark```

Since Pyshark is a TShark wrapper, Wireshark and TShark both need to be
installed for TShark to work. These can also be installed with `apt`:

```sudo apt-get install wireshark tshark```

Start up Wireshark at least once before attempting to use ELVis. This
creates a configuration folder ELVis can use to load the 4G/LTE
configuration profile.

ELVis should be correctly installed hereafter.

## Usage
The main functionality of ELVis can be achieved as follows:

```python3 main.py <.pcap>```

The following command loads a packet capture into ELVis and analyses
it. It then provides a visual representation of the `.pcap` file,
with different colors of arrows showing different levels of error.

Before using ELVis, you will probably want to get Wireshark/TShark
configured correctly. ELVis provides this functionality, by running
the following command:

```python3 main.py -config <directory>```

The `<directory>` is an optional argument you can pass along to ELVis
if your Wireshark stores the configuration profiles in a custom location.
By default, the configuration directory is set to
`/home/$USER/.config/wireshark`. 

If you want to configure Wireshark manually, the configuration files can
be found in the `profile` folder. Using a custom profile is also
possible with the `-profile <profile>` option. However, ELVis has only
been tested with its own configuration profile.

Other options include `-limit`, which limits the amount of packets
loaded into the script. This is especially useful when packet captures
are extremely large. There is also the `-filter` option, which allows
a display filter string to be put into the program. Only one filter
string can be loaded in.

In case you need a quick reference, using `-help` brings up a small
reference of all options that are used in ELVis.

## Limitations
Currently, ELVis does not analyse the entirety of the 4G/LTE protocol
stack. As it is right now, the program analyses the entire connection
establishment process in LTE. All analysed packets will be colored, all
packets which currently do not have the analysis provided will simply
be a black arrow and text.
