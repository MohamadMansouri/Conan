# Conan

## What is it about?
Conan is a network trafiic analyser that investigates pcap file, it reads the packets, reassembles all the TCP connections in the network trace, and for each connection it looks for any ambiguities.

## Motivations
This program is submitted as a project for the digital forensic course tought at **EURECOM** engineering school. It touches the need of an efficient, reliable and easy to use network traffic analyser to speed up and improve a network forensic operation. 

## What are the ambiguities it looks for?
Conan looks in each TCP connections for retransmitted packets, and investigates further in each of them, it checks if the retransmission was partially or fully retransmitted and checks if this retransmission holds new data or the same data ( the new data may overlap with the old one). It also checks for multiple MacAddresses and multiple time to live used in one connection. 

## How does it work?
* Checking for multiple MacAddresses used in each connection.
    
    For each connection the program looks in the source and destination MacAddress in each packet of each side of the connection, if it finds a packet with a MacAddress different than the one used before by this side it flags this connection and saves the MacAddresses with the data carried in the payload.
* Checking for multiple time to live (TTL) used in each connection.

    For each connection the program looks in the TTL in each packet of each side of the connection, if it finds a packet with a TTL different than the one used before by this side it flags this connection and saves the TTLs with the data carried in the payload.
* Investigates the TCP retransmissions in each connection

    For each connection the program looks in the retransmitted files, and keeps a flag that indicates if this retransmission was a fully or partially retransmitted, then it looks in the data retransmitted and tries to check if this data is different than the data sent in the previous packet of this side then it saves the old and new data (if the retransmitted packet is not the previous packet it just saves the new data).
    The program is capable to deal with out of order packets, TCP keep-alive messages and missing packets even if the missing packets were the very first packets in the connection.

## What is it composed of?
The project is build on the PcapPlusPlus library, you can find all the library files in this repository, I wrote a library file **"Conan.cpp"** for the program to do its job. **"Conan.cpp"** is a modification of the "TcpReassembly.cpp" file which I used as a base code and added about 800 lines of code their to do the job, the "TcpReassembly.cpp" is removed to grantee a successful compilation. This project right now supports only linux system, but the code is prepared to be upgraded to work on windows system, it just needs a configuration file to create the right make file to do the job.   

## Usage

conan [-hvwmsa] [-r input_file] [-o output_dir] [-e bpf_filter] [-f max_files] [-n cnx_number_1 cnx_number_2 ... ]

Options:

    -r input_file       : Input pcap/pcapng file to analyze. Required argument for reading from file
    -o output_dir       : Specify output directory (default is '.')
    -e bpf_filter       : Apply a BPF filter to capture file or live interface, meaning TCP reassembly will only work on filtered packets
    -f max_files        : Maximum number of file descriptors to use
    -n cnx_number_1 ... : Choose a specific connections to display in output 
    -w                  : Write TCP data for each connection to files 
    -m                  : Write a metadata file for each connection
    -s                  : Write each side of each connection to a separate file (default is writing both sides of each connection to the same file)
    -a                  : Print only connection that has any ambiguity
    -v                  : Set the verbose of the output (possible values are 0,1,2 (default 0))
    -h                  : Display this help message and exit

## Launching it

### Prerequisites 
You need to have the libpcap library on your machine. To install it type `sudo apt-get install libpcap-dev`.
### Compilation
Just type `make all`
### Execution
You will find the executable in the Bin directory, Example: `Bin/conan -r ~/sample.pcap` 
