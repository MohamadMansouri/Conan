#ifndef PACKETPP_TCP_REASSEMBLY
#define PACKETPP_TCP_REASSEMBLY

#include "Packet.h"
#include "IpAddress.h"
#include "PointerVector.h"
#include "MacAddress.h"
#include <string.h> 
#include <map>

/**
 * @file
 * This is an modified verson of the previous implementation of TCP reassembly logic, which means reassembly of TCP messages spanning multiple TCP segments (or packets).<BR>
 * This logic can be useful in analyzing messages for a large number of protocols implemented on top of TCP including HTTP, SSL/TLS, FTP and many many more. The modification 
 * aims to create a TCP analyser which investigates connections and looks for ambiguities.
 *
 * __General Features:__
 * - Manage multiple TCP connections under one pcpp#TcpReassembly instance
 * - Support TCP retransmission
 * - Support out-of-order packets
 * - Support missing TCP data
 * - TCP connections can end "naturally" (by FIN/RST packets) or manually by the user
 * - Support callbacks for new TCP data, connection start and connection end
 *
 * __General Features (NEW):__
 * - Checking for multiple MacAddresses used in each connection
 * - Checking for multiple time to live (TTL) used in each connection.
 * - Investigates the TCP retransmissions in each connection
 *
 * __Logic Description:__
 * - The user creates an instance of the pcpp#TcpReassembly class
 * - Then the user starts feeding it with TCP packets
 * - The pcpp#TcpReassembly instance manages all TCP connections from the packets it's being fed. For each connection it manages its 2 sides (A->B and B->A)
 * - When a packet arrives, it is first classified to a certain TCP connection
 * - Then it is classified to a certain side of the TCP connection
 * - Then the pcpp#TcpReassembly logic tries to understand if the data in this packet is the expected data (sequence-wise) and if it's new (e.g isn't a retransmission)
 * - If the packet data matches these criteria a callback is being invoked. This callback is supplied by the user in the creation of the pcpp#TcpReassembly instance. This callback contains
 *   the new data (of course), but also information about the connection (5-tuple, 4-byte hash key describing the connection, etc.) and also a pointer to a "user cookie", meaning a pointer to
 *   a structure provided by the user during the creation of the pcpp#TcpReassembly instance
 * - If the data in this packet isn't new, it's being ignored
 * - If the data in this packet isn't expected (meaning this packet came out-of-order), then the data is being queued internally and will be sent to the user when its turn arrives
 *   (meaning, after the data before arrives)
 * - If the missing data doesn't arrive until a new message from the other side of the connection arrives or until the connection ends - this will be considered as missing data and the
 *   queued data will be sent to the user, but the string "[X bytes missing]" will be added to the message sent in the callback
 * - pcpp#TcpReassembly supports 2 more callbacks - one is invoked when a new TCP connection is first seen and the other when it's ended (either by a FIN/RST packet or manually by the user).
 *   Both of these callbacks contain data about the connection (5-tuple, 4-byte hash key describing the connection, etc.) and also a pointer to a "user cookie", meaning a pointer to a
 *   structure provided by the user during the creation of the pcpp#TcpReassembly instance. The end connection callback also provides the reason for closing it ("naturally" or manually)
 *
 * __Logic Description (NEW):__
 * - For each connection the program looks in the source and destination MacAddress in each packet of each side of the connection, if it finds a packet with a MacAddress different than 
 *   the one used before by this side it flags this connection and saves the MacAddresses with the data carried in the payload.
 * - For each connection the program looks in the TTL in each packet of each side of the connection, if it finds a packet with a TTL different than the one used before by this side it flags
 *   this connection and saves the TTLs with the data carried in the payload.
 * - For each connection the program looks in the retransmitted files, and keeps a flag that indicates if this retransmission was a fully or partially retransmitted, then it looks in the data retransmitted and tries to check if this data is different than the data sent in the previous packet of this side then it saves the old and new data (if the retransmitted packet is not the previous packet it just saves the new data).
     The program is capable to deal with out of order packets, TCP keep-alive messages and missing packets even if the missing packets were the very first packets in the connection.

     
 * __Basic Usage and APIs:__
 * - pcpp#TcpReassembly c'tor - Create an instance, provide the callbacks and the user cookie to the instance
 * - pcpp#TcpReassembly#ReassemblePacket() - Feed pcpp#TcpReassembly instance with packets
 * - pcpp#TcpReassembly#closeConnection() - Manually close a connection by a flow key
 * - pcpp#TcpReassembly#closeAllConnections() - Manually close all currently opened connections
 * - pcpp#TcpReassembly#OnTcpMessageReady callback - Invoked when new data arrives on a certain connection. Contains the new data as well as connection data (5-tuple, flow key)
 * - pcpp#TcpReassembly#OnTcpConnectionStart callback - Invoked when a new connection is identified
 * - pcpp#TcpReassembly#OnTcpConnectionEnd callback - Invoked when a connection ends (either by FIN/RST or manually by the user)
 */

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * @struct connectionAnalysisStruct
 * Represents a retransmission instance in a connection
 */
struct retransmission
{
	/* flag to indicate pratially retransmission */
	bool partialRetransmission;
	/* flag to indicate full retransmission */
	bool fullRetransmission;
	/* flag to indicate transmissions with data different than the data retransmitted */
	bool transmissionWithNewData;
	/* size of the old data */
	size_t oldDataLength;
	/* pointer to old data */
	uint8_t* oldData;
	/* packet number of the old data */
	int oldPacketNumber;
	/* size of the new data */
	size_t newDataLength;
	/* pointer to new data */
	uint8_t* newData;
	/* packet number of the new data */
	int newPacketNumber;
	/* offset of the new data ( -ve means that the retransmitted data does not belong to the previous packet) */
	int offset;

	/**
	* A c'tor for this struct that basically zeros all members
	*/	
	retransmission();
	/**
	* A d'tor for this strcut. Notice it frees the memory of old data and new data members
	*/
	~retransmission();
	/**
	* A copy constructor for this struct.
	*/	
	retransmission(const retransmission& other);
	/**
	* An assignment operator for this struct.
	*/	
	retransmission& operator=(const retransmission& other);
	
private:

	void copyData(const retransmission& other);

};



/**
 * @struct connectionAnalysisStruct
 * Represents flags and variables about each connection
 */
struct connectionAnalysisStruct
{
	/* the 2 sides IP addresses */
	IPAddress* IP[2];
	/* the 2 sides port numbers */
	size_t Port[2];
	/* a vector to store all the source MacAddresses used in the connection */
	std::vector<MacAddress> srcMac[2];
	/* a vector to store all the destination MacAddresses used in the connection */
	std::vector<MacAddress> dstMac[2];
	/* a vector to store all the TTLs used in the connection */
	std::vector<uint8_t> ttl[2];
	/* a vector to store all the retransmission instances found in the connection */
	std::vector<retransmission> retransmitted[2];
	/* the length of the data sent with the new source MacAddress of each side */
	size_t newSrcMacDataLength[2];
	/* pointer to the data sent with the new source MacAddress of each side */
	uint8_t* newSrcMacData[2];
	/* the length of the data sent with the new destinaton MacAddress of each side */
	size_t newDstMacDataLength[2];
	/* pointer to the data sent with the new destination MacAddress of each side */
	uint8_t* newDstMacData[2];	
	/* the length of the data sent with the new TTL of each side */
	size_t newTtlDataLength[2];
	/* pointer to the data sent with the new TTL of each side */
	uint8_t* newTtlData[2];
	/* a holder of the previous packet number of each side */
	int packetNumber[2];
	/* a holder of the previous data length of each side */
	size_t dataLength[2];
	/* a holder of the pointer of the previous data of each side */
	uint8_t* data[2];
	/* the initial sequence the connection is opened with */
	uint32_t initialSeq[2];
	/*
	 * flag to indicate a weired connection. A weired connection is a one that has a retransmitted packet
	 * of an uncaptured packet that has a sequence number less than the sequence number of the first packet seen in this connection
	*/
	bool weired;
	

	/**
	* A c'tor for this struct that basically zeros all members
	*/	
	connectionAnalysisStruct() ;
	/**
	* A d'tor for this strcut. Notice it frees the memory of all the pointer and clear all the vectors
	*/
	~connectionAnalysisStruct();
	/**
	* An assignment operator for this struct.
	*/	
	connectionAnalysisStruct& operator=(const connectionAnalysisStruct& other);
	/**
	 * Set First side IP
	 * @param[in] sourceIP A pointer to the source IP to set. Notice the IPAddress object will be cloned
	 */
	void setSideZeroIP(const IPAddress* sourceIP) { IP[0] = sourceIP->clone(); }
	/**
	 * Set Second side IP
	 * @param[in] destIP A pointer to the destination IP to set. Notice the IPAddress object will be cloned
	 */
	void setSideOneIP(const IPAddress* destIP) { IP[1] = destIP->clone(); }
	/**
	* checks for new source MacAddresss, new destination MacAddresss and new TTL Then adds them to their corresponding vector and save the packets payload
	*/
	void pushNewData(int sideIndex, MacAddress sourceMac, MacAddress destinationMac, uint8_t timeToLive, uint8_t* data, size_t dataLength);

private:

	void copyData(const connectionAnalysisStruct& other);
};


/**
 * @struct ConnectionData
 * Represents basic TCP/UDP + IP connection data
 */
struct ConnectionData
{
	/** Source IP address */
	IPAddress* srcIP;
	/** Destination IP address */
	IPAddress* dstIP;
	/** Source TCP/UDP port */
	size_t srcPort;
	/** Destination TCP/UDP port */
	size_t dstPort;
	/** A 4-byte hash key representing the connection */
	uint32_t flowKey;

	/**
	 * A c'tor for this struct that basically zeros all members
	 */
	ConnectionData() : srcIP(NULL), dstIP(NULL), srcPort(0), dstPort(0), flowKey(0){}

	/**
	 * A d'tor for this strcut. Notice it frees the memory of srcIP and dstIP members
	 */
	~ConnectionData();

	/**
	 * A copy constructor for this struct. Notice it clones ConnectionData#srcIP and ConnectionData#dstIP
	 */
	ConnectionData(const ConnectionData& other);

	/**
	 * An assignment operator for this struct. Notice it clones ConnectionData#srcIP and ConnectionData#dstIP
	 */
	ConnectionData& operator=(const ConnectionData& other);

	/**
	 * Set source IP
	 * @param[in] sourceIP A pointer to the source IP to set. Notice the IPAddress object will be cloned
	 */
	void setSrcIpAddress(const IPAddress* sourceIP) { srcIP = sourceIP->clone(); }

	/**
	 * Set destination IP
	 * @param[in] destIP A pointer to the destination IP to set. Notice the IPAddress object will be cloned
	 */
	void setDstIpAddress(const IPAddress* destIP) { dstIP = destIP->clone(); }
	


private:

	void copyData(const ConnectionData& other);
};


class TcpReassembly;


/**
 * @class TcpStreamData
 * When following a TCP connection each packet may contain a piece of the data transferred between the client and the server. This class represents these pieces: each instance of it
 * contains a piece of data, usually extracted from a single packet, as well as information about the connection
 */
class TcpStreamData
{
	friend class TcpReassembly;

public:

	/**
	 * A c'tor for this class that basically zeros all members
	 */
	TcpStreamData();

	/**
	 * A c'tor for this class that get data from outside and set the internal members. Notice that when this class is destroyed it also frees the TCP data it stores
	 * @param[in] tcpData A buffer containing the TCP data piece
	 * @param[in] tcpDataLength The length of the buffer
	 * @param[in] connData TCP connection information for this TCP data
	 */
	TcpStreamData(uint8_t* tcpData, size_t tcpDataLength, ConnectionData connData);

	/**
	 * A d'tor for this class
	 */
	~TcpStreamData();

	/**
	 * A copy c'tor for this class. Notice the data buffer is copied from the source instance to this instance, so even if the source instance is destroyed the data in this instance
	 * stays valid. When this instance is destroyed it also frees the data buffer
	 * @param[in] other The instance to copy from
	 */
	TcpStreamData(TcpStreamData& other);

	/**
	 * Overload of the assignment operator. Notice the data buffer is copied from the source instance to this instance, so even if the source instance is destroyed the data in this instance
	 * stays valid. When this instance is destroyed it also frees the data buffer
	 * @param[in] other The instance to copy from
	 * @return A reference to this instance
	 */
	TcpStreamData& operator=(const TcpStreamData& other);

	/**
	 * A getter for the data buffer
	 * @return A pointer to the buffer
	 */
	inline uint8_t* getData() { return m_Data; }

	/**
	 * A getter for buffer length
	 * @return Buffer length
	 */
	inline size_t getDataLength() { return m_DataLen; }

	/**
	 * A getter for the connection data
	 * @return The connection data
	 */
	inline ConnectionData getConnectionData() { return m_Connection; }

private:
	uint8_t* m_Data;
	size_t m_DataLen;
	ConnectionData m_Connection;
	bool m_DeleteDataOnDestruction;

	void setDeleteDataOnDestruction(bool flag) { m_DeleteDataOnDestruction = flag; }
	void copyData(const TcpStreamData& other);
};


/**
 * @class TcpReassembly
 * A class containing the TCP reassembly logic. Please refer to the documentation at the top of TcpReassembly.h for understanding how to use this class
 */
class TcpReassembly
{
public:

	/**
	 * An enum for connection end reasons
	 */
	enum ConnectionEndReason
	{
		/** Connection ended because of FIN or RST packet */
		TcpReassemblyConnectionClosedByFIN_RST,
		/** Connection ended manually by the user */
		TcpReassemblyConnectionClosedManually
	};

	/**
	 * @typedef OnTcpMessageReady
	 * A callback invoked when new data arrives on a connection
	 * @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where 0 is the first side seen in the connection and 1 is the second side seen
	 * @param[in] tcpData The TCP data itself + connection information
	 * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly c'tor (or NULL if no cookie provided)
	 */
	typedef void (*OnTcpMessageReady)(int side, TcpStreamData tcpData, void* userCookie);

	/**
	 * @typedef OnTcpConnectionStart
	 * A callback invoked when a new TCP connection is identified (whether it begins with a SYN packet or not)
	 * @param[in] connectionData Connection information
	 * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly c'tor (or NULL if no cookie provided)
	 */
	typedef void (*OnTcpConnectionStart)(ConnectionData connectionData, void* userCookie);

	/**
	 * @typedef OnTcpConnectionEnd
	 * A callback invoked when a TCP connection is terminated, either by a FIN or RST packet or manually by the user
	 * @param[in] connectionData Connection information
	 * @param[in] reason The reason for connection termination: FIN/RST packet or manually by the user
	 * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly c'tor (or NULL if no cookie provided)
	 **********************************************++++++++++++++++++++++++++++++++++________________________
	 */
	typedef void (*OnTcpConnectionEnd)(connectionAnalysisStruct* endedConnection,ConnectionData connectionData, ConnectionEndReason reason, void* userCookie,  int* cnxNumber, int cnxNumberLength);

	/**
	 * A c'tor for this class
	 * @param[in] onMessageReadyCallback The callback to be invoked when new data arrives
	 * @param[in] userCookie A pointer to an object provided by the user. This pointer will be returned when invoking the various callbacks. This parameter is optional, default cookie is NULL
	 * @param[in] onConnectionStartCallback The callback to be invoked when a new connection is identified. This parameter is optional
	 * @param[in] onConnectionEndCallback The callback to be invoked when a new connection is terminated (either by a FIN/RST packet or manually by the user). This parameter is optional
	 */
	TcpReassembly(OnTcpMessageReady onMessageReadyCallback, void* userCookie = NULL, OnTcpConnectionStart onConnectionStartCallback = NULL, OnTcpConnectionEnd onConnectionEndCallback = NULL, int* cnxNumber =NULL, int cnxNumberLength =0);

	/**
	 * A d'tor for this class. Frees all internal structures. Notice that if the d'tor is called while connections are still open, all data is lost and TcpReassembly#OnTcpConnectionEnd won't
	 * be called for those connections
	 */
	~TcpReassembly();

	/**
	 * The most important method of this class which gets a packet from the user and processes it. If this packet opens a new connection, ends a connection or contains new data on an
	 * existing connection, the relevant callback will be called (TcpReassembly#OnTcpMessageReady, TcpReassembly#OnTcpConnectionStart, TcpReassembly#OnTcpConnectionEnd)
	 * @param[in] tcpData A reference to the packet to process
	 */
	void reassemblePacket(Packet& tcpData , bool Overlaped, std::map<uint32_t, connectionAnalysisStruct*> &ConnAnalysis);

	/**
	 * The most important method of this class which gets a raw packet from the user and processes it. If this packet opens a new connection, ends a connection or contains new data on an
	 * existing connection, the relevant callback will be invoked (TcpReassembly#OnTcpMessageReady, TcpReassembly#OnTcpConnectionStart, TcpReassembly#OnTcpConnectionEnd)
	 * @param[in] tcpRawData A reference to the raw packet to process
	 */
	void reassemblePacket(RawPacket* tcpRawData,  std::map<uint32_t, connectionAnalysisStruct*> &ConnAnalysis);

	/**
	 * Close a connection manually. If the connection doesn't exist or already closed an error log is printed. This method will cause the TcpReassembly#OnTcpConnectionEnd to be invoked with
	 * a reason of TcpReassembly#TcpReassemblyConnectionClosedManually
	 * @param[in] flowKey A 4-byte hash key representing the connection. Can be taken from a ConnectionData instance
	 */
	void closeConnection(uint32_t flowKey, std::map<uint32_t, connectionAnalysisStruct*> &ConnAnalysis);

	/**
	 * Close all open connections manually. This method will cause the TcpReassembly#OnTcpConnectionEnd to be invoked for each connection with a reason of
	 * TcpReassembly#TcpReassemblyConnectionClosedManually
	 */
	void closeAllConnections( std::map<uint32_t, connectionAnalysisStruct*> &ConnAnalysis);

	/**
	 * Get a list of all connections managed by this TcpReassembly instance (both connections that are open and those that are already closed)
	 * @return A list of all connections managed. Notice this list is constant and cannot be changed by the user
	 */
	const std::vector<ConnectionData>& getConnectionInformation() const;

	/**
	 * Check if a certain connection managed by this TcpReassembly instance is currently opened or closed
	 * @param[in] connection The connection to check
	 * @return A positive number (> 0) if connection is opened, zero (0) if connection is closed, and a negative number (< 0) if this connection isn't managed by this TcpReassembly instance
	 */
	int isConnectionOpen(const ConnectionData& connection);

private:
	struct TcpFragment
	{
		uint32_t sequence;
		size_t dataLength;
		uint8_t* data;
		int count;

		TcpFragment() { sequence = 0; dataLength = 0; data = NULL; }
		~TcpFragment() { if (data != NULL) delete [] data; }
	};

	struct TcpOneSideData
	{
		IPAddress* srcIP;
		uint16_t srcPort;
		uint32_t sequence;
		uint32_t prevSequence;
		PointerVector<TcpFragment> tcpFragmentList;
		bool gotFinOrRst;

		void setSrcIP(IPAddress* sourrcIP);


		TcpOneSideData() { srcIP = NULL; srcPort = 0; sequence = 0; prevSequence=0; gotFinOrRst = false;  }

		~TcpOneSideData() { if (srcIP != NULL) delete srcIP; }
	};

	struct TcpReassemblyData
	{
		int numOfSides;
		int prevSide;
		TcpOneSideData twoSides[2];
		ConnectionData connData;

		TcpReassemblyData() { numOfSides = 0; prevSide = -1; }
	};

	OnTcpMessageReady m_OnMessageReadyCallback;
	OnTcpConnectionStart m_OnConnStart;
	OnTcpConnectionEnd m_OnConnEnd;
	void* m_UserCookie;
	std::map<uint32_t, TcpReassemblyData*> m_ConnectionList;
	std::map<uint32_t, bool> m_ClosedConnectionList;
	std::vector<ConnectionData> m_ConnectionInfo;
	int* m_cnxNumber;
	int m_cnxNumberLength;

	void checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, int sideIndex, bool cleanWholeFragList , connectionAnalysisStruct* connAnalysisTemp);

	std::string prepareMissingDataMessage(uint32_t missingDataLen);

	void handleFinOrRst(TcpReassemblyData* tcpReassemblyData, int sideIndex, uint32_t flowKey, std::map<uint32_t, connectionAnalysisStruct*> &ConnAnalysis);

	void closeConnectionInternal(uint32_t flowKey, ConnectionEndReason reason, std::map<uint32_t, connectionAnalysisStruct*> &ConnAnalysis);
};

}

#endif /* PACKETPP_TCP_REASSEMBLY */
