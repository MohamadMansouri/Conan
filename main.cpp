/**
 * TcpReassembly application
 * =========================
 * This is an application that captures data transmitted as part of TCP connections, organizes the data and stores it in a way that is convenient for protocol analysis and debugging.
 * This application reconstructs the TCP data streams and stores each connection in a separate file(s). TcpReassembly understands TCP sequence numbers and will correctly reconstruct
 * data streams regardless of retransmissions, out-of-order delivery or data loss.
 * TcpReassembly works more or less the same like tcpflow (https://linux.die.net/man/1/tcpflow) but probably with less options.
 * The main purpose of it is to demonstrate the TCP reassembly capabilities in PcapPlusPlus.
 * Main features and capabilities:
 *   - Captures packets from pcap/pcapng files or live traffic
 *   - Handles TCP retransmission, out-of-order packets and packet loss
 *   - Possibility to set a BPF filter to process only part of the traffic
 *   - Write each connection to a separate file
 *   - Write each side of each connection to a separate file
 *   - Limit the max number of open files in each point in time (to avoid running out of file descriptors for large files / heavy traffic)
 *   - Write a metadata file (txt file) for each connection with various stats on the connection: number of packets (in each side + total), number of TCP messages (in each side + total),
 *     number of bytes (in each side + total)
 *   - Write to console only (instead of files)
 *   - Set a directory to write files to (default is current directory)
 *
 * For more details about modes of operation and parameters run TcpReassembly -h
 */


#include <stdlib.h>
#include <stdio.h>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include "Conan.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "LRUList.h"
#include "SystemUtils.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"



#include <getopt.h>
#include "Logger.h"

using namespace pcpp;

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)


#if defined(WIN32) || defined(WINx64)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif


const std::string red("\033[0;31m");
const std::string green("\033[1;32m");
const std::string yellow("\033[1;33m");
const std::string cyan("\033[0;36m");
const std::string magenta("\033[0;35m");
const std::string reset("\033[0m");

// unless the user chooses otherwise - default number of concurrent used file descriptors is 1000
#define DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES 1000


static struct option TcpAssemblyOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"input-file",  required_argument, 0, 'r'},
	{"output-dir", required_argument, 0, 'o'},
	{"list-interfaces", no_argument, 0, 'l'},
	{"filter", required_argument, 0, 'e'},
	{"write-metadata", no_argument, 0, 'm'},
	{"write-data-to-file", no_argument, 0, 'w'},
	{"separate-sides", no_argument, 0, 's'},
	{"max-file-desc", required_argument, 0, 'f'},
	{"connection-number", required_argument, 0, 'n'},
	{"print-only-ambiguities", no_argument, 0, 'a'},
	{"verbose", required_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};


/**
 * A singleton class containing the configuration as requested by the user. This singleton is used throughout the application
 */
class GlobalConfig
{
private:

	/**
	 * A private c'tor (as this is a singleton)
	 */
	GlobalConfig() { writeMetadata = false; outputDir = ""; writeData = true; separateSides = false; printAll = true; maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES; m_RecentConnsWithActivity = NULL; verbose =0; ambiguities=0;}

	// A least-recently-used (LRU) list of all connections seen so far. Each connection is represented by its flow key. This LRU list is used to decide which connection was seen least
	// recently in case we reached max number of open file descriptors and we need to decide which files to close
	LRUList<uint32_t>* m_RecentConnsWithActivity;

public:

	// a flag indicating whether to write a metadata file for each connection (containing several stats)
	bool writeMetadata;

	// the directory to write files to (default is current directory)
	std::string outputDir;

	// a bool indicating whether to write TCP data to files default is true
	int writeData;

	// a flag indicating whether to write both side of a connection to the same file (which is the default) or write each side to a separate file
	bool separateSides;

	// max number of allowed open files in each point in time
	size_t maxOpenFiles;

	// verbose of the output, integer of range 0 to 2
	int verbose;

	// number of ambiguity connections found
	int ambiguities; 

	// a flag to indicate if prints all connections or only ambiguous ones (default is all)
	bool printAll;
	/**
	 * A method getting connection parameters as input and returns a filename and file path as output.
	 * The filename is constructed by the IPs (src and dst) and the TCP ports (src and dst)
	 */
	std::string getFileName(ConnectionData connData, int side, bool separareSides)
	{
		std::stringstream stream;

		// if user chooses to write to a directory other than the current directory - add the dir path to the return value
		if (outputDir != "")
			stream << outputDir << SEPARATOR;

		std::string sourceIP = connData.srcIP->toString();
		std::string destIP = connData.dstIP->toString();

		// for IPv6 addresses, replace ':' with '_'
		std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
		std::replace(destIP.begin(), destIP.end(), ':', '_');

		// side == 0 means data is sent from client->server
		if (side <= 0 || separareSides == false)
			stream << sourceIP << "." << connData.srcPort << "-" << destIP << "." << connData.dstPort;

		else // side == 1 means data is sent from server->client
			stream << destIP << "." << connData.dstPort << "-" << sourceIP << "." << connData.srcPort;

		// return the file path
		return stream.str();
	}


	/**
	 * Open a file stream. Inputs are the filename to open and a flag indicating whether to append to an existing file or overwrite it.
	 * Return value is a pointer to the new file stream
	 */
	std::ostream* openFileStream(std::string fileName, bool reopen)
	{
		
		// open the file on the disk (with append or overwrite mode)
		if (reopen)
			return new std::ofstream(fileName.c_str(), std::ios_base::binary | std::ios_base::app);
		else
			return new std::ofstream(fileName.c_str(), std::ios_base::binary);
	}


	/**
	 * Close a file stream
	 */
	void closeFileSteam(std::ostream* fileStream)
	{

			// close the file stream
			std::ofstream* fstream = (std::ofstream*)fileStream;
			fstream->close();

			// free the memory of the file stream
			delete fstream;

	}


	/**
	 * Return a pointer to the least-recently-used (LRU) list of connections
	 */
	LRUList<uint32_t>* getRecentConnsWithActivity()
	{
		// his is a lazy implementation - the instance isn't created until the user requests it for the first time.
		// the side of the LRU list is determined by the max number of allowed open files at any point in time. Default is DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES
		// but the user can choose another number
		if (m_RecentConnsWithActivity == NULL)
			m_RecentConnsWithActivity = new LRUList<uint32_t>(maxOpenFiles);

		// return the pointer
		return m_RecentConnsWithActivity;
	}


	/**
	 * The singleton implementation of this class
	 */
	static inline GlobalConfig& getInstance()
	{
		static GlobalConfig instance;
		return instance;
	}
};


/**
 * A struct to contain all data save on a specific connection. It contains the file streams to write to and also stats data on the connection
 */
struct TcpReassemblyData
{
	// pointer to 2 file stream - one for each side of the connection. If the user chooses to write both sides to the same file (which is the default), only one file stream is used (index 0)
	std::ostream* fileStreams[2];

	// flags indicating whether the file in each side was already opened before. If the answer is yes, next time it'll be opened in append mode (and not in overwrite mode)
	bool reopenFileStreams[2];

	// a flag indicating on which side was the latest message on this connection
	int curSide;

	// stats data: num of data packets on each side, bytes seen on each side and messages seen on each side
	int numOfDataPackets[2];
	int numOfMessagesFromSide[2];
	int bytesFromSide[2];




	/**
	 * the default c'tor
	 */
	TcpReassemblyData() { fileStreams[0] = NULL; fileStreams[1] = NULL;  clear(); }

	/**
	 * The default d'tor
	 */
	~TcpReassemblyData()
	{
		// close files on both sides if open
		if (fileStreams[0] != NULL)
			GlobalConfig::getInstance().closeFileSteam(fileStreams[0]);

		if (fileStreams[1] != NULL)
			GlobalConfig::getInstance().closeFileSteam(fileStreams[1]);
	}

	/**
	 * Clear all data (put 0, false or NULL - whatever relevant for each field)
	 */
	void clear()
	{
		// for the file stream - close them if they're not null
		if (fileStreams[0] != NULL)
		{
			GlobalConfig::getInstance().closeFileSteam(fileStreams[0]);
			fileStreams[0] = NULL;
		}

		if (fileStreams[1] != NULL)
		{
			GlobalConfig::getInstance().closeFileSteam(fileStreams[1]);
			fileStreams[1] = NULL;
		}

		reopenFileStreams[0] = false;
		reopenFileStreams[1] = false;
		numOfDataPackets[0] = 0;
		numOfDataPackets[1] = 0;
		numOfMessagesFromSide[0] = 0;
		numOfMessagesFromSide[1] = 0;
		bytesFromSide[0] = 0;
		bytesFromSide[1] = 0;
		curSide = -1;

	}
};


// typedef representing the connection manager and its iterator
typedef std::map<uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;
typedef std::map<uint32_t, TcpReassemblyData>::iterator TcpReassemblyConnMgrIter;


/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage:\n"
			"------\n"
			"%s [-hvwmsa] [-r input_file] [-o output_dir] [-e bpf_filter] [-f max_files] [-n cnx_number_1 cnx_number_2 ... ]\n"
			"\nOptions:\n\n"
			"    -r input_file       : Input pcap/pcapng file to analyze. Required argument for reading from file\n"
			"    -o output_dir       : Specify output directory (default is '.')\n"
			"    -e bpf_filter       : Apply a BPF filter to capture file or live interface, meaning TCP reassembly will only work on filtered packets\n"
			"    -f max_files        : Maximum number of file descriptors to use\n"
			"    -n cnx_number_1 ... : Choose a specific connections to display in output \n"
			"    -w                  : Write TCP data for each connection to files \n"
			"    -m                  : Write a metadata file for each connection\n"
			"    -s                  : Write each side of each connection to a separate file (default is writing both sides of each connection to the same file)\n"
			"    -a                  : Print only connection that has any ambiguity\n"
			"    -v                  : Set the verbose of the output (possible values are 0,1,2 (default 0))\n"
			"    -h                  : Display this help message and exit\n\n", AppName::get().c_str());

	exit(0);
}




/**
 * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
 */
static void tcpReassemblyMsgReadyCallback(int sideIndex, TcpStreamData tcpData, void* userCookie)
{
	// extract the connection manager from the user cookie
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	// check if this flow already appears in the connection manager. If not add it
	TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);
	if (iter == connMgr->end())
	{
		connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData()));
		iter = connMgr->find(tcpData.getConnectionData().flowKey);
	}

	int side;

	// if the user wants to write each side in a different file - set side as the sideIndex, otherwise write everything to the same file ("side 0")
	if (GlobalConfig::getInstance().separateSides)
		side = sideIndex;
	else
		side = 0;

	// if the file stream on the relevant side isn't open yet (meaning it's the first data on this connection)
	if (iter->second.fileStreams[side] == NULL)
	{
		// add the flow key of this connection to the list of open connections. If the return value isn't NULL it means that there are too many open files
		// and we need to close the connection with least recently used file(s) in order to open a new one.
		// The connection with the least recently used file is the return value
		uint32_t* flowKeyToCloseFiles = GlobalConfig::getInstance().getRecentConnsWithActivity()->put(tcpData.getConnectionData().flowKey);

		// if flowKeyToCloseFiles isn't NULL it means we need to close the open files in this connection (the one with the least recently used files)
		if (flowKeyToCloseFiles != NULL)
		{
			// find the connection from the flow key
			TcpReassemblyConnMgrIter iter2 = connMgr->find(*flowKeyToCloseFiles);
			if (iter2 != connMgr->end())
			{
				// close files on both sides (if they're open)
				for (int index = 0; index < 1; index++)
				{
					if (iter2->second.fileStreams[index] != NULL)
					{
						// close the file
						GlobalConfig::getInstance().closeFileSteam(iter2->second.fileStreams[index]);
						iter2->second.fileStreams[index] = NULL;

						// set the reopen flag to true to indicate that next time this file will be opened it will be opened in append mode (and not overwrite mode)
						iter2->second.reopenFileStreams[index] = true;
					}
				}
			}
		}

		// get the file name according to the 5-tuple etc.
		std::string fileName = GlobalConfig::getInstance().getFileName(tcpData.getConnectionData(), sideIndex, GlobalConfig::getInstance().separateSides) + ".txt";
		// open the file in overwrite mode (if this is the first time the file is opened) or in append mode (if it was already opened before)
		iter->second.fileStreams[side] = GlobalConfig::getInstance().openFileStream(fileName, iter->second.reopenFileStreams[side]);
	}

	// if this messages comes on a different side than previous message seen on this connection
	if (sideIndex != iter->second.curSide)
	{
		// count number of message in each side
		iter->second.numOfMessagesFromSide[sideIndex]++;

		// set side index as the current active side
		iter->second.curSide = sideIndex;
	}

	// count number of packets and bytes in each side of the connection
	iter->second.numOfDataPackets[sideIndex]++;
	iter->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

	// write the new data to the file
	iter->second.fileStreams[side]->write((char*)tcpData.getData(), tcpData.getDataLength());
}


/**
 * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the connection to the connection manager
 */
static void tcpReassemblyConnectionStartCallback(ConnectionData connectionData, void* userCookie)
{
	// get a pointer to the connection manager
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	// look for the connection in the connection manager
	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);
	
	std::string sourceIP = connectionData.srcIP->toString();
	std::string destIP = connectionData.dstIP->toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');
	//std::cout << "First Side : [" << sourceIP << ":" << connectionData.srcPort << "] Second Side : [" << destIP << ":" << connectionData.dstPort << "] " << std::endl ;

	// assuming it's a new connection
	if (iter == connMgr->end())
	{
		// add it to the connection manager
		connMgr->insert(std::make_pair(connectionData.flowKey, TcpReassemblyData()));
	//	std::cout << "First Side : [" << sourceIP << ":" << czonnectionData.srcPort << "] Second Side : [" << destIP << ":" << connectionData.dstPort << "]" << std::endl ;

	}
}


int checkMultipleMac (std::vector<MacAddress> srcMac[2], std::vector<MacAddress> dstMac[2])
{
	if (srcMac[0].size() > 1)
		return 1;

	 if (srcMac[1].size() > 1)
		return 2;
	 
	 if (dstMac[0].size() > 1)
	 	return 3;
	 
	 if (dstMac[1].size() > 1 )
		return 4;
	
	return 0;
}

int checkMultipleTtl (std::vector<uint8_t> ttl[2])
{
	if (ttl[0].size() > 1)
		return 1;

	 if (ttl[1].size() > 1)
		return 2;

	return 0;
}

void printData (uint8_t* data , size_t dataLength)
{
	for(size_t i=0; i<dataLength ; i++)
		printf(" 0x%X", *(data+i));
	printf("\n");
}

void
print_hex_ascii_line(const uint8_t *payload, size_t len)
{
	std::cout << cyan;

	size_t i;
	size_t gap;
	const uint8_t *ch;

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	std::cout << magenta;
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
	std::cout << reset;
	printf("\n\n");

return;
}


bool checkCnxNumber (int count, int* cnxNumber, int cnxNumberLength)
{
	if (cnxNumberLength != 0)
		for(int i=0; i<cnxNumberLength ; i++ )
			if(count == cnxNumber[i])
				return true;
	return false;
}

/**
 * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the connection from the connection manager and writes the metadata file if requested
 * by the user
 */
static void tcpReassemblyConnectionEndCallback(connectionAnalysisStruct* endedConnection, ConnectionData connectionData, TcpReassembly::ConnectionEndReason reason, void* userCookie, int* cnxNumber, int cnxNumberLength)
{
	static int count=0;
	bool ambiguous = false;
	count ++;

	//check if it contains multiple macAddresses
	int multipleMac = checkMultipleMac(endedConnection->srcMac, endedConnection->dstMac);
	int multipleTtl = checkMultipleTtl(endedConnection->ttl);

	if(!endedConnection->retransmitted[0].empty() || !endedConnection->retransmitted[1].empty() || (bool)multipleMac || (bool)multipleTtl)
		{
			GlobalConfig::getInstance().ambiguities++;
			ambiguous = true;
		}

	if ( checkCnxNumber(count,cnxNumber,cnxNumberLength) || ( !(bool)cnxNumberLength && (GlobalConfig::getInstance().printAll || ambiguous) ))
	{
		// get a pointer to the connection manager
		TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

		// find the connection in the connection manager by the flow key
		TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

		// connection wasn't found - shouldn't get here
		if (iter == connMgr->end())
			return;
		
		std::string sourceIP = endedConnection->IP[0]->toString();
		std::string destIP = endedConnection->IP[1]->toString();
		size_t srcPort = endedConnection->Port[0];
		size_t dstPort = endedConnection->Port[1]; 
		// for IPv6 addresses, replace ':' with '_'


		std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
		std::replace(destIP.begin(), destIP.end(), ':', '_');
		std::cout.setf(std::ios::boolalpha);

		std::cout << "["<< std::left << std::setw(3) << count << "] " << 
		"First Side : [" << std::left << std::setw(15) << sourceIP << ":" << std::setw(5) << srcPort <<
		"] Second Side : [" << std::left << std::setw(15) << destIP << ":" << std::setw(5) << dstPort << "] retransmission : [ ";
		if (!endedConnection->retransmitted[0].empty() || !endedConnection->retransmitted[1].empty())
			std::cout << red <<"true " << reset;
		else
			std::cout << "false";
		std::cout << " ] Multiple MacAddreses : [ ";
		if ((bool)multipleMac)
			std::cout << red <<"true " << reset;
		else
			std::cout << "false";
		std::cout << " ] Multiple TTL : [ " ;
		if ((bool)multipleTtl)
			std::cout << red <<"true  " << reset << "]";
		else
			std::cout << "false ]";
		 std::cout << std::endl ;

		int multipleMacIndex = checkMultipleMac(endedConnection->srcMac, endedConnection->dstMac);
		int multipleTtlIndex = checkMultipleTtl(endedConnection->ttl);
		if (GlobalConfig::getInstance().verbose > 0 )
		 {
	 		std::cout << yellow ;
		 	if(!endedConnection->retransmitted[0].empty() || multipleMacIndex == 1 || multipleMacIndex == 2 ||  multipleTtlIndex == 1)
		 	{
	 			printf("    Side 1:\n");
		 	
	 			if (multipleMacIndex == 1)
 				{
	 				std::cout << yellow ;
 					printf("    -->Source MacAdresses used in the connection are: ");
 					for ( uint i=0;i < endedConnection->srcMac[0].size() ; i++)
 						printf("%s ",endedConnection->srcMac[0].at(i).toString().c_str() );
 					if (GlobalConfig::getInstance().verbose == 2)
 					{
		 				std::cout << cyan;
						printf("\n Data sent with different source macaddress (Length = %d)\n",(int)(endedConnection->newSrcMacDataLength[0]));
						printf("-------------------------------------------\n");
		 				print_hex_ascii_line(endedConnection->newSrcMacData[0],endedConnection->newSrcMacDataLength[0]);
		 				std::cout << reset;	
 					}
 					else 
 						printf("\n");				

 				}
	 			if (multipleMacIndex == 2)
 				{
	 				std::cout << yellow ;
 					printf("    -->Destination MacAdresses used in the connection are: ");
 					for ( uint i=0;i < endedConnection->dstMac[0].size() ; i++)
 						printf("%s ",endedConnection->dstMac[0].at(i).toString().c_str() );
 				
 					if (GlobalConfig::getInstance().verbose == 2)
 					{
		 				std::cout << cyan;
						printf("\n Data sent with different destination macaddress (Length = %d)\n",(int)(endedConnection->newDstMacDataLength[0]));
						printf("------------------------------------------------\n");
		 				print_hex_ascii_line(endedConnection->newDstMacData[0],endedConnection->newDstMacDataLength[0]);
		 				std::cout << reset;	
 					} 
 					else 
 						printf("\n");				
 				}

	 			if (multipleTtlIndex == 1)
	 			{
 					std::cout << yellow ;
					printf("    -->TTLs used in the connection are: ");
 					for ( uint i=0;i < endedConnection->ttl[0].size() ; i++)
 						printf("%d ",endedConnection->ttl[0].at(i) );
	 				if (GlobalConfig::getInstance().verbose == 2)
 					{
		 				std::cout << cyan;
						printf("\n Data sent with different TTL (Length = %d)\n",(int)(endedConnection->newTtlDataLength[0]));
						printf("-----------------------------\n");
		 				print_hex_ascii_line(endedConnection->newTtlData[0],endedConnection->newTtlDataLength[0]);
		 				std::cout << reset;	
 					}
 					else
	 					printf("\n");


	 			}

			 	if (!endedConnection->retransmitted[0].empty())
			 	{
			 		for(uint i = 0; i < endedConnection->retransmitted[0].size(); i++)
			 		{
			 			std::cout << yellow ;
			 			printf("    -->Packet Number %d is ",endedConnection->retransmitted[0].at(i).oldPacketNumber);
			 			if(endedConnection->retransmitted[0].at(i).partialRetransmission)
			 				printf("partially retransmitted ");
			 			else if (endedConnection->retransmitted[0].at(i).fullRetransmission)
			 				printf("fully retransmitted ");
			 			else
			 				printf("retransmitted ");
			 			if(endedConnection->retransmitted[0].at(i).transmissionWithNewData && endedConnection->retransmitted[0].at(i).newData != NULL && endedConnection->retransmitted[0].at(i).newDataLength != 0 )
			 			{
			 				printf("in packet number %d ",endedConnection->retransmitted[0].at(i).newPacketNumber);
			 				printf("with new data\n");
			 				if (GlobalConfig::getInstance().verbose == 2)
			 				{
				 				std::cout << cyan;
								printf("\nOld Data (Length = %d)\n",(int)(endedConnection->retransmitted[0].at(i).oldDataLength));
								printf("--------\n");
				 				print_hex_ascii_line(endedConnection->retransmitted[0].at(i).oldData,endedConnection->retransmitted[0].at(i).oldDataLength);
				 				std::cout << cyan;
								printf("\nNew Data (Length = %d)\n",(int)(endedConnection->retransmitted[0].at(i).newDataLength));
								printf("--------\n");
				 				print_hex_ascii_line(endedConnection->retransmitted[0].at(i).newData,endedConnection->retransmitted[0].at(i).newDataLength);
				 				std::cout << reset;
				 			}
			 			}
			 			else
			 				printf("in packet number %d with same data\n",endedConnection->retransmitted[0].at(i).newPacketNumber);
			 		}
			 	}
			 	printf("\n");
		 	}
		 	if(!endedConnection->retransmitted[1].empty() || multipleMacIndex == 3 || multipleMacIndex == 4 ||  multipleTtlIndex == 2)
		 	{
	 			printf("    Side 2:\n");
		 	
	 			if (multipleMacIndex == 3)
 				{
 					printf("    -->Source MacAdresses used in the connection are: ");
 					for ( uint i=0;i < endedConnection->srcMac[1].size() ; i++)
 						printf("%s ",endedConnection->srcMac[1].at(i).toString().c_str() );

 					if (GlobalConfig::getInstance().verbose == 2)
 					{
		 				std::cout << cyan;
						printf("\n Data sent with different source macaddress (Length = %d)\n",(int)(endedConnection->newSrcMacDataLength[1]));
						printf("-------------------------------------------\n");
		 				print_hex_ascii_line(endedConnection->newSrcMacData[1],endedConnection->newSrcMacDataLength[1]);
		 				std::cout << reset;	
 					}
 					else 
 						printf("\n");				
 						


 				}
	 			if (multipleMacIndex == 4)
 				{
 					printf("    -->Destination MacAdresses used in the connection are: ");
 					for ( uint i=0;i < endedConnection->dstMac[1].size() ; i++)
 						printf("%s ",endedConnection->dstMac[1].at(i).toString().c_str() );
 					if (GlobalConfig::getInstance().verbose == 2)
 					{
		 				std::cout << cyan;
						printf("\n Data sent with different source macaddress (Length = %d)\n",(int)(endedConnection->newSrcMacDataLength[1]));
						printf("-------------------------------------------\n");
		 				print_hex_ascii_line(endedConnection->newSrcMacData[1],endedConnection->newSrcMacDataLength[1]);
		 				std::cout << reset;	
 					}
 					else 
 						printf("\n");				
 						

 				}

	 			if (multipleTtlIndex == 2)
	 				{
						printf("    -->TTLs used in the connection are: ");
	 					for ( uint i=0;i < endedConnection->ttl[1].size() ; i++)
	 						printf("%d ",endedConnection->ttl[1].at(i) );
	 					printf("\n");

	 				if (GlobalConfig::getInstance().verbose == 2)
 					{
		 				std::cout << cyan;
						printf("\n Data sent with different TTL (Length = %d)\n",(int)(endedConnection->newTtlDataLength[1]));
						printf("-----------------------------\n");
		 				print_hex_ascii_line(endedConnection->newTtlData[1],endedConnection->newTtlDataLength[1]);
		 				std::cout << reset;	
 					}
 					else
	 					printf("\n");	 					
	 				}

			 	if (!endedConnection->retransmitted[1].empty())
			 	{
			 		for(uint i = 0; i < endedConnection->retransmitted[1].size(); i++)
			 		{
			 			std::cout << yellow ;
			 			printf("    -->Packet Number %d is ",endedConnection->retransmitted[1].at(i).oldPacketNumber);
			 			if(endedConnection->retransmitted[1].at(i).partialRetransmission)
			 				printf("partially retransmitted ");
			 			else if (endedConnection->retransmitted[1].at(i).fullRetransmission)
			 				printf("fully retransmitted ");
			 			else
			 				printf("retransmitted ");
			 			if(endedConnection->retransmitted[1].at(i).transmissionWithNewData && endedConnection->retransmitted[1].at(i).newData != NULL && endedConnection->retransmitted[1].at(i).newDataLength != 0 )			 			{
			 				printf("in packet number %d ",endedConnection->retransmitted[0].at(i).newPacketNumber);
			 				printf("with new data\n");
			 				if (GlobalConfig::getInstance().verbose == 2)
			 				{
				 				std::cout << cyan;
								printf("\nOld Data (Length = %d)\n",(int)(endedConnection->retransmitted[1].at(i).oldDataLength));
								printf("--------\n");
				 				print_hex_ascii_line(endedConnection->retransmitted[1].at(i).oldData,endedConnection->retransmitted[1].at(i).oldDataLength);
				 				std::cout << cyan;
								printf("\nNew Data (Length = %d)\n",(int)(endedConnection->retransmitted[1].at(i).newDataLength));
								printf("--------\n");
				 				print_hex_ascii_line(endedConnection->retransmitted[1].at(i).newData,endedConnection->retransmitted[1].at(i).newDataLength);
				 				std::cout << reset;
				 			}
			 			}
			 			else
			 				printf("in packet number %d with same data\n",endedConnection->retransmitted[1].at(i).newPacketNumber);
			 		}
			 	}
		 	}
		 	std::cout << reset ;
		 }

		// write a metadata file if required by the user
		if (GlobalConfig::getInstance().writeMetadata)
		{
			std::string fileName = GlobalConfig::getInstance().getFileName(connectionData, 0, false) + "-metadata.txt";
			std::ofstream metadataFile(fileName.c_str());
			metadataFile << "Number of data packets in side 1:  " << iter->second.numOfDataPackets[0] << std::endl;
			metadataFile << "Number of data packets in side 2:  " << iter->second.numOfDataPackets[1] << std::endl;
			metadataFile << "Total number of data packets:      " << (iter->second.numOfDataPackets[0] + iter->second.numOfDataPackets[1]) << std::endl;
			metadataFile << std::endl;
			metadataFile << "Number of bytes in side 1:         " << iter->second.bytesFromSide[0] << std::endl;
			metadataFile << "Number of bytes in side 2:         " << iter->second.bytesFromSide[1] << std::endl;
			metadataFile << "Total number of bytes:             " << (iter->second.bytesFromSide[0] + iter->second.bytesFromSide[1]) << std::endl;
			metadataFile << std::endl;
			metadataFile << "Number of messages in side 1:      " << iter->second.numOfMessagesFromSide[0] << std::endl;
			metadataFile << "Number of messages in side 2:      " << iter->second.numOfMessagesFromSide[1] << std::endl;
			metadataFile.close();
		}
	}
}




std::map<uint32_t,connectionAnalysisStruct*> connAnalysis;

/**
 * The method responsible for TCP reassembly on pcap/pcapng files
 */
void proccessTCPpacket(std::string fileName, TcpReassembly& tcpReassembly, std::string bpfFiler = "")
{
	// open input file (pcap or pcapng file)
	IFileReaderDevice* reader = IFileReaderDevice::getReader(fileName.c_str());

	// try to open the file device
	if (!reader->open())
		EXIT_WITH_ERROR("Cannot open pcap/pcapng file");

	// set BPF filter if set by the user
	if (bpfFiler != "")
	{
		if (!reader->setFilter(bpfFiler))
			EXIT_WITH_ERROR("Cannot set BPF filter to pcap file");
	}

	printf("Starting reading '%s'...\n", fileName.c_str());

	// run in a loop that reads one packet from the file in each iteration and feeds it to the TCP reassembly instance
	RawPacket rawPacket;
	
	while (reader->getNextPacket(rawPacket))
	{	
		Packet parsedPacket(&rawPacket);		
		tcpReassembly.reassemblePacket(parsedPacket,false, connAnalysis);
	}

	// extract number of connectionions before closing all of them
	size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

	// after all packets have been read - close the connections which are still opened

	tcpReassembly.closeAllConnections(connAnalysis);

	// close the reader and free its memory
	reader->close();
	delete reader;

	printf("Done! processed %d connections\n", (int)numOfConnectionsProcessed);
	printf("Found %d ambiguous connections\n", (int)GlobalConfig::getInstance().ambiguities);

}





/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	std::string interfaceNameOrIP = "";
	std::string inputPcapFileName = "";
	std::string bpfFilter = "";
	std::string outputDir = "";
	bool writeMetadata = false;
	bool writeData = false;
	bool separateSides = false;
	bool printAll = true;
	int* cnxNumber = NULL;
	int cnxNumberLength = 0;
	int verbose = 0;
	size_t maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;
	
	int optionIndex = 0;
	char opt = 0;
	std::string next;
	int index;
	int cnxCount = 0;
	while((opt = getopt_long (argc, argv, "r:o:e:f:n:v:amwsvhl", TcpAssemblyOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'r':
				inputPcapFileName = optarg;
				break;
			case 'o':
				outputDir = optarg;
				break;
			case 'e':
				bpfFilter = optarg;
				break;
			case 's':
				separateSides = true;
				break;
			case 'm':
				writeMetadata = true;
				break;
			case 'w':
				writeData = true;
				break;
			case 'f':
				maxOpenFiles = (size_t)atoi(optarg);
				break;
			case 'n':
 			{
 				index = optind-1;
	            while(index < argc)
	            {
	                next = strdup(argv[index]); /* get login */
	                index++;
	                if(next[0] != '-')
	                {         /* check if optarg is next switch */
	                    cnxNumberLength++;
	                }
	                else break;
	            }
	            
	            cnxNumber = new int[cnxNumberLength];
	            index = optind-1;
	            
	            while(index < argc)
	            {
	                next = strdup(argv[index]); /* get login */
	                index++;
	                if(next[0] != '-')
	                {        
	                    cnxNumber[cnxCount++] = atoi(next.c_str());
	                }
	                else break;
	            }
            }
				break;
			case 'v':
				verbose = atoi(optarg);
				break;
			case 'a':
				printAll = false;
				break;
			case 'h':
				printUsage();
				break;
			default:
				printUsage();
				exit(-1);
		}
	}
	// if no interface nor input pcap file were provided - exit with error
	if (inputPcapFileName == "")
		EXIT_WITH_ERROR("Input pcap file were not provided");

	// verify output dir exists
	if (outputDir != "" && !directoryExists(outputDir))
		EXIT_WITH_ERROR("Output directory doesn't exist");

	// set global config singleton with input configuration
	GlobalConfig::getInstance().outputDir = outputDir;
	GlobalConfig::getInstance().writeMetadata = writeMetadata;
	GlobalConfig::getInstance().writeData = writeData;
	GlobalConfig::getInstance().separateSides = separateSides;
	GlobalConfig::getInstance().maxOpenFiles = maxOpenFiles;
	GlobalConfig::getInstance().verbose = verbose;
	GlobalConfig::getInstance().printAll = printAll;
	//LoggerPP::getInstance().setLogLevel(PacketLogModuleTcpReassembly,LoggerPP::LogLevel::Debug);
	LoggerPP::getInstance().supressErrors();
	//printf("%d\n",IS_DEBUG);

	// create the object which manages info on all connections
	TcpReassemblyConnMgr connMgr;

	void (*msgReadyCallback) (int side, TcpStreamData tcpData, void* userCookie)= NULL;
	if (writeData)
		msgReadyCallback = tcpReassemblyMsgReadyCallback;
	
	// create the TCP reassembly instance
	TcpReassembly tcpReassembly(msgReadyCallback, &connMgr, tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback, cnxNumber, cnxNumberLength);
	// analyze packets from pcap file
	proccessTCPpacket(inputPcapFileName, tcpReassembly, bpfFilter);
}
