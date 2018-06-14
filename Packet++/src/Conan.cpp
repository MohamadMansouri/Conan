#define LOG_MODULE PacketLogModuleTcpReassembly

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include "Conan.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PacketUtils.h"
#include "IpAddress.h"
#include "Logger.h"
#include "EthLayer.h"
#include "MacAddress.h"	
#include <string.h> 
#include <sstream>
#ifdef WIN32 //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#include <algorithm> 
#endif


namespace pcpp
{

retransmission::retransmission()
{
	partialRetransmission=false;
	fullRetransmission=false;
	transmissionWithNewData=false;
	oldDataLength=0;
	oldData=NULL;
	oldPacketNumber=0;
	newDataLength=0;
	newData=NULL;
	newPacketNumber=0;
	offset=0;


}

retransmission::~retransmission()
{
	if (oldData != NULL) delete [] oldData;
	if (newData != NULL) delete [] newData;
}

retransmission::retransmission(const retransmission& other)
{
	copyData(other);
}


retransmission& retransmission::operator=(const retransmission& other)
{
	if (oldData != NULL)
		delete oldData;
	if (newData != NULL)
		delete newData;
	copyData(other);
	return *this;
}

void retransmission::copyData(const retransmission& other)
{
	partialRetransmission = other.partialRetransmission;
	fullRetransmission = other.fullRetransmission;
	transmissionWithNewData = other.transmissionWithNewData;
	oldDataLength = other.oldDataLength;
	oldPacketNumber = other.oldPacketNumber;
	newDataLength = other.newDataLength;
	newPacketNumber = other.newPacketNumber;
	offset = other.offset;
	if (other.oldData != NULL)
	{
		oldData = new uint8_t[oldDataLength];
		memcpy(oldData,other.oldData,oldDataLength);
	}
	else 
		oldData = NULL;

	if (other.newData != NULL)
	{
		newData = new uint8_t[newDataLength];
		memcpy(newData,other.newData,newDataLength);
	}
	else 
		newData = NULL;
}


connectionAnalysisStruct::connectionAnalysisStruct()
{
	 IP[0] = NULL;
	 IP[1] = NULL;

	 Port[0] = 0;
	 Port[1] = 0;

	 packetNumber[0]=0;
	 packetNumber[1]=0;

	dataLength[0] = 0 ;
	dataLength[1] = 0 ;
	
	data[0] = NULL;
	data[1] = NULL;

	newSrcMacDataLength[0] = 0;
	newSrcMacDataLength[1] = 0;

	newDstMacDataLength[0] = 0;
	newDstMacDataLength[1] = 0;

	newSrcMacData[0] = NULL;
	newSrcMacData[1] = NULL;

	newDstMacData[0] = NULL;
	newDstMacData[1] = NULL;
	
	newTtlDataLength[0] = 0;
	newTtlDataLength[1] = 0;
	
	newTtlData[0] = NULL;
	newTtlData[1] = NULL;

	initialSeq[0] = 0;
	initialSeq[1] = 0;
	weired = false;
}

connectionAnalysisStruct::~connectionAnalysisStruct()
{
	if (IP[0] != NULL) 
		delete IP[0]; 

	if (IP[1] != NULL) 
		delete IP[1]; 

	if (data[0] != NULL)
		delete data[0];

	if (data[1] != NULL)
		delete data[1];

	if (newSrcMacData[0] != NULL)
		delete newSrcMacData[0];
	
	if (newSrcMacData[1] != NULL)
		delete newSrcMacData[1];
	
	if (newDstMacData[1] != NULL)
		delete newDstMacData[1];

	if (newDstMacData[0] != NULL)
		delete newDstMacData[0];
	
	if (newTtlData[1] != NULL)
		delete newTtlData[1];

	srcMac[0].clear(); 
	srcMac[1].clear(); 
	dstMac[0].clear();
	dstMac[1].clear(); 
	ttl[0].clear(); 
	ttl[1].clear();
	retransmitted[0].clear();
	retransmitted[1].clear();
}
connectionAnalysisStruct& connectionAnalysisStruct::operator=(const connectionAnalysisStruct& other)
{
	if (IP[0] != NULL) 
		delete IP[0]; 

	if (IP[1] != NULL) 
		delete IP[1]; 

	if (data[0] != NULL)
		delete data[0];

	if (data[1] != NULL)
		delete data[1];

	if (newSrcMacData[0] != NULL)
		delete newSrcMacData[0];
	
	if (newSrcMacData[1] != NULL)
		delete newSrcMacData[1];
	
	if (newDstMacData[1] != NULL)
		delete newDstMacData[1];

	if (newDstMacData[0] != NULL)
		delete newDstMacData[0];
	
	if (newTtlData[1] != NULL)
		delete newTtlData[1];

	copyData(other); 
	return *this;
}

void connectionAnalysisStruct::copyData(const connectionAnalysisStruct& other)
{
	if (other.IP[0] != NULL) 
		IP[0] = other.IP[0]->clone();
	else
		IP[0] = NULL;

	if (other.IP[1] != NULL) 
		IP[1] = other.IP[1]->clone();
	else
		IP[1] = NULL;
	
	Port[0]=other.Port[0];
	Port[1]=other.Port[1];
	ttl[0] = other.ttl[0];
	ttl[1] = other.ttl[1];
	srcMac[0] = other.srcMac[0];
	srcMac[1] = other.srcMac[1];
	dstMac[0] = other.dstMac[0];
	dstMac[1] = other.dstMac[1];
	retransmitted[0] = other.retransmitted[0];
	retransmitted[1] = other.retransmitted[1];
	packetNumber[0] = other.packetNumber[0];
	packetNumber[1] = other.packetNumber[1];
	dataLength[0] = other.dataLength[0];
	dataLength[1] = other.dataLength[1];
	newSrcMacDataLength[0] = other.newSrcMacDataLength[0];
	newSrcMacDataLength[1] = other.newSrcMacDataLength[1];
	newDstMacDataLength[0] = other.newDstMacDataLength[0];
	newDstMacDataLength[1] = other.newDstMacDataLength[1];
	newTtlDataLength[0] = other.newTtlDataLength[0];
	newTtlDataLength[1] = other.newTtlDataLength[1];
	initialSeq[0] = other.initialSeq[0];
	initialSeq[1] = other.initialSeq[1];
	weired = other.weired;


	if (other.data[0] != NULL)
	{
		data[0] = new uint8_t[dataLength[0]];
		memcpy(data[0],other.data[0],dataLength[0]);
	}
	else
		data[0] = NULL;

	if (other.data[1] != NULL)
	{
		data[1] = new uint8_t[dataLength[1]];
		memcpy(data[1],other.data[1],dataLength[1]);
	}
	else
		data[1] = NULL;
	
	if (other.newSrcMacData[0] != NULL)
	{
		newSrcMacData[0] = new uint8_t[newSrcMacDataLength[0]];
		memcpy(newSrcMacData[0],other.newSrcMacData[0],newSrcMacDataLength[0]);
	}
	else
		newSrcMacData[0] = NULL;

	if (other.newSrcMacData[1] != NULL)
	{
		newSrcMacData[1] = new uint8_t[newSrcMacDataLength[1]];
		memcpy(newSrcMacData[1],other.newSrcMacData[1],newSrcMacDataLength[1]);
	}
	else
		newSrcMacData[1] = NULL;
	
	if (other.newDstMacData[0] != NULL)
	{
		newDstMacData[0] = new uint8_t[newDstMacDataLength[0]];
		memcpy(newDstMacData[0],other.newDstMacData[0],newDstMacDataLength[0]);
	}
	else
		newDstMacData[0] = NULL;

	if (other.newDstMacData[1] != NULL)
	{
		newDstMacData[1] = new uint8_t[newDstMacDataLength[1]];
		memcpy(newDstMacData[1],other.newDstMacData[1],newDstMacDataLength[1]);
	}
	else
		newDstMacData[1] = NULL;

	if (other.newTtlData[0] != NULL)
	{
		newTtlData[0] = new uint8_t[newTtlDataLength[0]];
		memcpy(newTtlData[0],other.newTtlData[0],newTtlDataLength[0]);
	}
	else
		newTtlData[0] = NULL;

	if (other.newTtlData[1] != NULL)
	{
		newTtlData[1] = new uint8_t[newTtlDataLength[1]];
		memcpy(newTtlData[1],other.newTtlData[1],newTtlDataLength[1]);
	}
	else
		newTtlData[1] = NULL;
}



void connectionAnalysisStruct::pushNewData(int sideIndex, MacAddress sourceMac, MacAddress destinationMac, uint8_t timeToLive, uint8_t* data, size_t dataLength)
{
	std::vector<MacAddress>::iterator macIt;
	macIt = find(srcMac[sideIndex].begin(),srcMac[sideIndex].end(),sourceMac); 
	if (macIt == srcMac[sideIndex].end())
	{
		if (!srcMac[sideIndex].empty())
		{
			if (data !=NULL && dataLength != 0)
			{
				if (newSrcMacData[sideIndex] == NULL)
				{
					newSrcMacDataLength[sideIndex] = dataLength;
					newSrcMacData[sideIndex] = new uint8_t[newSrcMacDataLength[sideIndex]];
					memcpy(newSrcMacData[sideIndex],data,newSrcMacDataLength[sideIndex]);
				}
				else 
				{
					uint8_t* tmpData = new uint8_t[newSrcMacDataLength[sideIndex] + dataLength];
					memcpy(tmpData,newSrcMacData[sideIndex],newSrcMacDataLength[sideIndex]);
					memcpy(tmpData+newSrcMacDataLength[sideIndex],data, dataLength);
					delete newSrcMacData[sideIndex];
					newSrcMacDataLength[sideIndex] += dataLength;
					newSrcMacData[sideIndex] = new uint8_t[newSrcMacDataLength[sideIndex]];
					memcpy(newSrcMacData[sideIndex],tmpData,newSrcMacDataLength[sideIndex]);
					delete tmpData; 


				}
			}
		}
		srcMac[sideIndex].push_back(sourceMac);

	}
	
	macIt = find(dstMac[sideIndex].begin(),dstMac[sideIndex].end(),destinationMac); 
	if (macIt == dstMac[sideIndex].end())
	{
		if (!dstMac[sideIndex].empty())
		{
			if (data !=NULL && dataLength != 0)
			{
				if (newDstMacData[sideIndex] == NULL)
				{
					newDstMacDataLength[sideIndex] = dataLength;
					newDstMacData[sideIndex] = new uint8_t[newDstMacDataLength[sideIndex]];
					memcpy(newDstMacData[sideIndex],data,newDstMacDataLength[sideIndex]);
				}
				else 
				{
					uint8_t* tmpData = new uint8_t[newDstMacDataLength[sideIndex] + dataLength];
					memcpy(tmpData,newDstMacData[sideIndex],newDstMacDataLength[sideIndex]);
					memcpy(tmpData+newDstMacDataLength[sideIndex],data, dataLength);
					delete newDstMacData[sideIndex];
					newDstMacDataLength[sideIndex] += dataLength;
					newDstMacData[sideIndex] = new uint8_t[newDstMacDataLength[sideIndex]];
					memcpy(newDstMacData[sideIndex],tmpData,newDstMacDataLength[sideIndex]);
					delete tmpData; 


				}
			}
		}
		dstMac[sideIndex].push_back(destinationMac);
		
	}

	std::vector<uint8_t>::iterator ttlIt;
	ttlIt = find(ttl[sideIndex].begin(),ttl[sideIndex].end(),timeToLive); 
	if (ttlIt == ttl[sideIndex].end())
	{
		if (!ttl[sideIndex].empty())
		{
			if (data !=NULL && dataLength != 0)
			{
				if (newTtlData[sideIndex] == NULL)
				{
					newTtlDataLength[sideIndex] = dataLength;
					newTtlData[sideIndex] = new uint8_t[newTtlDataLength[sideIndex]];
					memcpy(newTtlData[sideIndex],data,newTtlDataLength[sideIndex]);
				}
				else 
				{
					uint8_t* tmpData = new uint8_t[newTtlDataLength[sideIndex] + dataLength];
					memcpy(tmpData,newTtlData[sideIndex],newTtlDataLength[sideIndex]);
					memcpy(tmpData+newTtlDataLength[sideIndex],data, dataLength);
					delete newTtlData[sideIndex];
					newTtlDataLength[sideIndex] += dataLength;
					newTtlData[sideIndex] = new uint8_t[newTtlDataLength[sideIndex]];
					memcpy(newTtlData[sideIndex],tmpData,newTtlDataLength[sideIndex]);
					delete tmpData; 


				}
			}
		}
		ttl[sideIndex].push_back(timeToLive);
	}

}


ConnectionData::~ConnectionData()
{
	if (srcIP != NULL)
		delete srcIP;

	if (dstIP != NULL)
		delete dstIP;
}

ConnectionData::ConnectionData(const ConnectionData& other)
{
	copyData(other);
}

ConnectionData& ConnectionData::operator=(const ConnectionData& other)
{
	if (srcIP != NULL)
		delete srcIP;

	if (dstIP != NULL)
		delete dstIP;

	copyData(other);

	return *this;
}

void ConnectionData::copyData(const ConnectionData& other)
{
	if (other.srcIP != NULL)
		srcIP = other.srcIP->clone();
	else
		srcIP = NULL;

	if (other.dstIP != NULL)
		dstIP = other.dstIP->clone();
	else
		dstIP = NULL;

	flowKey = other.flowKey;
	srcPort = other.srcPort;
	dstPort = other.dstPort;
}


TcpStreamData::TcpStreamData()
{
	m_Data = NULL;
	m_DataLen = 0;
	m_DeleteDataOnDestruction = false;
}

TcpStreamData::TcpStreamData(uint8_t* tcpData, size_t tcpDataLength, ConnectionData connData)
{
	m_Data = tcpData;
	m_DataLen = tcpDataLength;
	m_Connection = connData;
	m_DeleteDataOnDestruction = true;
}

TcpStreamData::~TcpStreamData()
{
	if (m_DeleteDataOnDestruction && m_Data != NULL)
	{
		delete [] m_Data;
	}
}

TcpStreamData::TcpStreamData(TcpStreamData& other)
{
	copyData(other);
}

TcpStreamData& TcpStreamData::operator=(const TcpStreamData& other)
{
	if (this == &other)
		return *this;

	if (m_DeleteDataOnDestruction && m_Data != NULL)
		delete [] m_Data;

	copyData(other);
	return *this;
}

void TcpStreamData::copyData(const TcpStreamData& other)
{
	m_DataLen = other.m_DataLen;

	if (other.m_Data != NULL)
	{
		m_Data = new uint8_t[m_DataLen];
		memcpy(m_Data, other.m_Data, m_DataLen);
	}
	else
		m_Data = NULL;

	m_Connection = other.m_Connection;
	m_DeleteDataOnDestruction = true;
}

void TcpReassembly::TcpOneSideData::setSrcIP(IPAddress* sourrcIP)
{
	if (srcIP != NULL)
		delete srcIP;

	srcIP = sourrcIP->clone();
}


TcpReassembly::TcpReassembly(OnTcpMessageReady onMessageReadyCallback, void* userCookie, OnTcpConnectionStart onConnectionStartCallback, OnTcpConnectionEnd onConnectionEndCallback,  int* cnxNumber, int cnxNumberLength)
{
	m_OnMessageReadyCallback = onMessageReadyCallback;
	m_UserCookie = userCookie;
	m_OnConnStart = onConnectionStartCallback;
	m_OnConnEnd = onConnectionEndCallback;
	m_cnxNumber = cnxNumber;
	m_cnxNumberLength =cnxNumberLength;
} 

TcpReassembly::~TcpReassembly()
{
	while (!m_ConnectionList.empty())
	{
		delete m_ConnectionList.begin()->second;
		m_ConnectionList.erase(m_ConnectionList.begin());
	}
}

void TcpReassembly::reassemblePacket(Packet& tcpData, bool Overlaped, std::map<uint32_t, connectionAnalysisStruct* > &connAnalysis)
{
	//counter for the packet number
	static int count=0;
	count++;
	// get IP layer
	Layer* ipLayer = NULL;
	if (tcpData.isPacketOfType(IPv4))
		ipLayer = (Layer*)tcpData.getLayerOfType<IPv4Layer>();
	else if (tcpData.isPacketOfType(IPv6))
		ipLayer = (Layer*)tcpData.getLayerOfType<IPv6Layer>();

	if (ipLayer == NULL)
		return;

	// get tcp layer
	TcpLayer* tcpLayer = tcpData.getLayerOfType<TcpLayer>();
	

	// Ignore non-TCP packets
	if (tcpLayer == NULL)
	{
		LOG_DEBUG("Ignoring Non TCP packet");
		return;
	}
	// get ethernet layer
	EthLayer* ethernetLayer =tcpData.getLayerOfType<EthLayer>();
	if (ethernetLayer == NULL)
	{
		LOG_DEBUG("Couldn't find Ethernet layer\n");
		return;
	}
	
	// calculate the TCP payload size
	size_t tcpPayloadSize = tcpLayer->getLayerPayloadSize();

	// calculate if this packet has FIN or RST flags
	bool isFin = (tcpLayer->getTcpHeader()->finFlag == 1);
	bool isRst = (tcpLayer->getTcpHeader()->rstFlag == 1);
	bool isFinOrRst = isFin || isRst;

	// ignore ACK packets or TCP packets with no payload (except for SYN, FIN or RST packets which we'll later need)
	if (tcpPayloadSize == 0 && tcpLayer->getTcpHeader()->synFlag == 0 && !isFinOrRst)
		return;

	// if the actual TCP payload is smaller than the value written in IPV4's "total length" field then adjust tcpPayloadSize to avoid buffer overflow
	if (tcpLayer->getLayerPayloadSize() < tcpPayloadSize)
	{
		LOG_DEBUG("Got a packet where actual TCP payload size is smaller then the value written in IPv4's 'total length' header. Adjusting tcpPayloadSize to avoid buffer overflow");
		tcpPayloadSize = tcpLayer->getLayerPayloadSize();
	}

	// create a TcpReassembly instance
	TcpReassemblyData* tcpReassemblyData = NULL;

	// calculate flow key for this packet
	uint32_t flowKey = hash5Tuple(&tcpData);
 
	// if this packet belongs to a connection that was already closed (for example: data packet that comes after FIN), ignore it
	if (m_ClosedConnectionList.find(flowKey) != m_ClosedConnectionList.end())
	{
		LOG_DEBUG("Ignoring packet of already closed flow [0x%X]", flowKey);
		return;
	}

	// calculate packet's source and dest IP address
	IPAddress* srcIP = NULL;
	IPAddress* dstIP = NULL;
	IPv4Address srcIP4Addr = IPv4Address::Zero;
	IPv6Address srcIP6Addr = IPv6Address::Zero;
	IPv4Address dstIP4Addr = IPv4Address::Zero;
	IPv6Address dstIP6Addr = IPv6Address::Zero;
	// calculate packet's source and dest MacAddress
	MacAddress sourceMac = ((EthLayer*)ethernetLayer)->getSourceMac();
	MacAddress destinationMac = ((EthLayer*)ethernetLayer)->getDestMac();

	// extract information from IP layer
	uint8_t ttl;
	if (ipLayer->getProtocol() == IPv4)
	{
		srcIP4Addr = ((IPv4Layer*)ipLayer)->getSrcIpAddress();
		srcIP = &srcIP4Addr;
		dstIP4Addr = ((IPv4Layer*)ipLayer)->getDstIpAddress();
		dstIP = &dstIP4Addr;
		ttl = ((IPv4Layer*)ipLayer)->getIPv4Header()->timeToLive;

	}
	else if (ipLayer->getProtocol() == IPv6)
	{
		srcIP6Addr = ((IPv6Layer*)ipLayer)->getSrcIpAddress();
		srcIP = &srcIP6Addr;
		dstIP6Addr = ((IPv6Layer*)ipLayer)->getDstIpAddress();
		dstIP = &dstIP6Addr;
		ttl = ((IPv6Layer*)ipLayer)->getIPv6Header()->hopLimit;

	}
	

	// find the connection in the connection map
	std::map<uint32_t, TcpReassemblyData*>::iterator iter = m_ConnectionList.find(flowKey);
	if (iter == m_ConnectionList.end())
	{
		// if it's a packet of a new connection, create a TcpReassemblyData object and add it to the active connection list
		tcpReassemblyData = new TcpReassemblyData();
		tcpReassemblyData->connData.setSrcIpAddress(srcIP);
		tcpReassemblyData->connData.setDstIpAddress(dstIP);
		tcpReassemblyData->connData.srcPort = ntohs(tcpLayer->getTcpHeader()->portSrc);
		tcpReassemblyData->connData.dstPort = ntohs(tcpLayer->getTcpHeader()->portDst);
		tcpReassemblyData->connData.flowKey= flowKey;
		m_ConnectionList[flowKey] = tcpReassemblyData;

		m_ConnectionInfo.push_back(tcpReassemblyData->connData);

		// fire connection start callback
		if (m_OnConnStart != NULL)
			m_OnConnStart(tcpReassemblyData->connData, m_UserCookie);
	}
	// connection already exists
	else 
		tcpReassemblyData = iter->second;

	// create a connectionAnalysisStruct Instance
	connectionAnalysisStruct* connAnalysisInst = NULL;
	
	// find the connection in the connection map
	std::map<uint32_t, connectionAnalysisStruct*>::iterator connectionAnalysisIter = connAnalysis.find(flowKey);
	if (connectionAnalysisIter == connAnalysis.end())
	{
		// if it's a packet of a new connection, create a connectionAnalysisStruct object and add it to the active connection list
		connAnalysisInst = new connectionAnalysisStruct();
		connAnalysis[flowKey]=connAnalysisInst;
	}
	// connection already exists	
	else 
		connAnalysisInst = connectionAnalysisIter->second;
	
	int sideIndex = -1;
	bool first = false;

	// calculate packet's source port
	uint16_t srcPort = ntohs(tcpLayer->getTcpHeader()->portSrc);
	uint16_t dstPort = ntohs(tcpLayer->getTcpHeader()->portDst);
	
	// if this is a new connection and it's the first packet we see on that connection
	if (tcpReassemblyData->numOfSides == 0)
	{
		LOG_DEBUG("Setting side for new connection");

		// open the first side of the connection, side index is 0
		sideIndex = 0;
		tcpReassemblyData->twoSides[sideIndex].setSrcIP(srcIP);
		tcpReassemblyData->twoSides[sideIndex].srcPort = srcPort;
		tcpReassemblyData->numOfSides++;

		connAnalysisInst->Port[sideIndex] = srcPort;
		//here we set the other side's port since some connectoins can only have one side (uncomplete connections)
		connAnalysisInst->Port[sideIndex+1] = dstPort;
		connAnalysisInst->setSideZeroIP(srcIP);
		connAnalysisInst->setSideOneIP(dstIP);

		first = true;
	}
	// if there is already one side in this connection (which will be at side index 0)
	else if (tcpReassemblyData->numOfSides == 1)
	{
		// check if packet belongs to that side
		if (tcpReassemblyData->twoSides[0].srcIP->equals(srcIP) && tcpReassemblyData->twoSides[0].srcPort == srcPort)
		{
			sideIndex = 0;
		}
		else
		{
			// this means packet belong to the second side which doesn't yet exist. Open a second side with side index 1
			LOG_DEBUG("Setting second side of a connection");
			sideIndex = 1;
			tcpReassemblyData->twoSides[sideIndex].setSrcIP(srcIP);
			tcpReassemblyData->twoSides[sideIndex].srcPort = srcPort;

			// the side port will be reset again (just to be more sure)
			connAnalysisInst->Port[sideIndex] = srcPort;
			connAnalysisInst->setSideZeroIP(srcIP);
			connAnalysisInst->setSideOneIP(dstIP);


			tcpReassemblyData->numOfSides++;
			first = true;
		}
	}
	// if there are already 2 sides open for this connection
	else if (tcpReassemblyData->numOfSides == 2)
	{
		// check if packet matches side 0
		if (tcpReassemblyData->twoSides[0].srcIP->equals(srcIP) && tcpReassemblyData->twoSides[0].srcPort == srcPort)
		{
			sideIndex = 0;
		}
		// check if packet matches side 1
		else if (tcpReassemblyData->twoSides[1].srcIP->equals(srcIP) && tcpReassemblyData->twoSides[1].srcPort == srcPort)
		{
			sideIndex = 1;
		}
		
		// packet doesn't match either side. This case doesn't make sense but it's handled anyway. Packet will be ignored
		else
		{
			LOG_ERROR("Error occurred - packet doesn't match either side of the connection!!");
			return;
		}
	}
	// there are more than 2 side - this case doesn't make sense and shouldn't happen, but handled anyway. Packet will be ignored
	else
	{
		LOG_ERROR("Error occurred - connection has more than 2 sides!!");
		return;
	}

	
	connAnalysisInst->pushNewData(sideIndex, sourceMac, destinationMac, ttl, tcpLayer->getLayerPayload(), tcpPayloadSize);


	// if this side already got FIN or RST packet before, ignore this packet as this side is considered closed
	if (tcpReassemblyData->twoSides[sideIndex].gotFinOrRst)
	{
		LOG_DEBUG("Got a packet after FIN or RST were already seen on this side (%d). Ignoring this packet", sideIndex);
		return;
	}

	// handle FIN/RST packets that don't contain additional TCP data
	if (isFinOrRst && tcpPayloadSize == 0)
	{
		LOG_DEBUG("Got FIN or RST packet without data on side %d", sideIndex);

		handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, connAnalysis);
		return;
	}
	
	uint32_t sequenceTemp = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);

	// check if this is a not a weired connection, skip the packet if it is
	if (first || sequenceTemp >= connAnalysisInst->initialSeq[sideIndex])
	{
		// check if this packet contains data from a different side than the side seen before.
		// If this is the case then treat the out-of-order packet list as missing data and send them to the user (callback) together with an indication that some data was missing.
		// Why? because a new packet from the other side means the previous message was probably already received and a new message is starting.
		// In this case out-of-order packets are probably actually missing data
		// For example: let's assume these are HTTP messages. If we're seeing the first packet of a response this means the server has already received the full request and is now starting
		// to send the response. So if we still have out-of-order packets from the request it probably means that some packets were lost during the capture. So we don't expect the client to
		// continue sending packets of the previous request, so we'll treat the out-of-order packets as missing data
		//
		// I'm aware that there are edge cases where the situation I described above is not true, but at some point we must clean the out-of-order packet list to avoid memory leak.
		// I decided to do what Wireshark does and clean this list when starting to see a message from the other side
		if (!first && tcpPayloadSize > 0 && tcpReassemblyData->prevSide != -1 && tcpReassemblyData->prevSide != sideIndex &&
				tcpReassemblyData->twoSides[tcpReassemblyData->prevSide].tcpFragmentList.size() > 0)
		{
			LOG_DEBUG("Seeing a first data packet from a different side. Previous side was %d, current side is %d", tcpReassemblyData->prevSide, sideIndex);
			checkOutOfOrderFragments(tcpReassemblyData, tcpReassemblyData->prevSide, true, connAnalysisInst);
		}
		tcpReassemblyData->prevSide = sideIndex;

		// extract sequence value from packet
		uint32_t sequence = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);

		// if it's the first packet we see on this side of the connection
		if (first)
		{
			// save the packet number 
			connAnalysisInst->packetNumber[sideIndex] = count;
			// save the initial sequence of each side
			connAnalysisInst->initialSeq[sideIndex] = sequence;

			// if this packet holds data save them for farther usage in next packets
			if (tcpPayloadSize != 0)
			{
				connAnalysisInst->dataLength[sideIndex] = tcpPayloadSize;
				connAnalysisInst->data[sideIndex] = new uint8_t[tcpPayloadSize];
				memcpy(connAnalysisInst->data[sideIndex],tcpLayer->getLayerPayload(),tcpPayloadSize);
			}

			LOG_DEBUG("First data from this side of the connection");

			// save the sequence for farther usage in next packets
			tcpReassemblyData->twoSides[sideIndex].prevSequence=sequence;
			// calculate the next expected sequence
			tcpReassemblyData->twoSides[sideIndex].sequence = sequence + tcpPayloadSize;
			if (tcpLayer->getTcpHeader()->synFlag != 0)
				tcpReassemblyData->twoSides[sideIndex].sequence++;
			


			// send data to the callback
			if (tcpPayloadSize != 0 && m_OnMessageReadyCallback != NULL)
			{
				TcpStreamData streamData(tcpLayer->getLayerPayload(), tcpPayloadSize, tcpReassemblyData->connData);
				streamData.setDeleteDataOnDestruction(false);
				m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
			}

			// handle case where this packet is FIN or RST (although it's unlikely)
			if (isFinOrRst)
				handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, connAnalysis);

			// return - nothing else to do here
			return;
		}
		// handle case where this packet is tcp keep-alive message (it should not match sine we skipped 0 data acks)
		if (sequence == tcpReassemblyData->twoSides[sideIndex].sequence - 1 && tcpPayloadSize == 0)
		{
				LOG_DEBUG("Received Tcp keep-alive message");

				// handle case where this packet is FIN or RST
				if (isFinOrRst)
					handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, connAnalysis);

				return;
		}

		// if packet sequence is smaller than expected - this means that part or all of the TCP data is being re-transmitted
		if (sequence < tcpReassemblyData->twoSides[sideIndex].sequence)
		{
			// extract the previous packet number
			int oldPacketNumber = connAnalysisInst->packetNumber[sideIndex];
			// save the packet number
			connAnalysisInst->packetNumber[sideIndex] = count;
			size_t dataLength;
			uint8_t* data;
			// extract the previous packet data
			if (connAnalysisInst->dataLength[sideIndex] != 0 && connAnalysisInst->data[sideIndex] != NULL)
			{
				dataLength = connAnalysisInst->dataLength[sideIndex];
				data = new uint8_t[dataLength];
				memcpy(data,connAnalysisInst->data[sideIndex],dataLength);
			}
			else
			{
				dataLength = 0;
				data = NULL;
			}
			// save the new packet data
			if (tcpPayloadSize != 0)
			{
				connAnalysisInst->dataLength[sideIndex] = tcpPayloadSize;
				connAnalysisInst->data[sideIndex] = new uint8_t[tcpPayloadSize];
				memcpy(connAnalysisInst->data[sideIndex],tcpLayer->getLayerPayload(),tcpPayloadSize);
			}


			LOG_DEBUG("Found new data with the sequence lower than expected");
			// create a retransmission instance
			retransmission retransInst;
			// calculate the previous data packet number
			retransInst.oldPacketNumber = oldPacketNumber; 
			// save the current packet number
			retransInst.newPacketNumber = count; 
			

			// calculate the data of the previous data packet 
			if (data != NULL)
			{
				retransInst.oldDataLength = dataLength;
				retransInst.oldData = new uint8_t[dataLength];
				memcpy(retransInst.oldData,data,dataLength);
			
				// if their is new data calculate them
				if ( retransInst.oldDataLength != tcpPayloadSize || memcmp(tcpLayer->getLayerPayload(),retransInst.oldData,tcpPayloadSize) )
				{
					//  the offset of the new data
					retransInst.offset = sequence - tcpReassemblyData->twoSides[sideIndex].prevSequence;

					retransInst.transmissionWithNewData = true;
					retransInst.newDataLength = tcpPayloadSize;
					retransInst.newData = new uint8_t[tcpPayloadSize];
					memcpy(retransInst.newData,tcpLayer->getLayerPayload(),tcpPayloadSize);
				}
			}
			else 
			{
				retransInst.oldDataLength = 0;
				retransInst.oldData = NULL;
				retransInst.newDataLength = 0;
				retransInst.newData = NULL;
			}


			// calculate the sequence after this packet to see if this TCP payload contains also new data
			uint32_t newSequence = sequence + tcpPayloadSize;

			// save if the packet is a full or partial retransmission of the previous packet
			if (tcpReassemblyData->twoSides[sideIndex].prevSequence == sequence)
				retransInst.fullRetransmission=true;
			else
				retransInst.partialRetransmission=true;

			connAnalysisInst->retransmitted[sideIndex].push_back(retransInst) ; 
			
			// this means that some of payload is new ( other than the retransmitted ones )
			if (newSequence > tcpReassemblyData->twoSides[sideIndex].sequence)
			{


				// calculate the size of the new data
				uint32_t newLength = tcpReassemblyData->twoSides[sideIndex].sequence - sequence;

				LOG_DEBUG("Although sequence is lower than expected payload is long enough to contain new data. Calling the callback with the new data");

				// update the sequence for this side to include the new data that was seen
				tcpReassemblyData->twoSides[sideIndex].sequence += tcpPayloadSize - newLength;

				// send only the new data to the callback
				if (m_OnMessageReadyCallback != NULL)
				{
					TcpStreamData streamData(tcpLayer->getLayerPayload() + newLength, tcpPayloadSize - newLength, tcpReassemblyData->connData);
					streamData.setDeleteDataOnDestruction(false);
					m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
				}
			}
			// Save the sequence as the previous sequence
			tcpReassemblyData->twoSides[sideIndex].prevSequence=sequence;

			// handle case where this packet is FIN or RST
			if (isFinOrRst)
				handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, connAnalysis);

			// return - nothing else to do here
			return;
		}

		// if packet sequence is exactly as expected - this is the "good" case and the most common one
		else if (sequence == tcpReassemblyData->twoSides[sideIndex].sequence)
		{

			// save the packet number
			connAnalysisInst->packetNumber[sideIndex] = count;

			// if this packet holds data save them for farther usage in next packets
			if (tcpPayloadSize != 0)
			{
				connAnalysisInst->dataLength[sideIndex] = tcpPayloadSize;
				connAnalysisInst->data[sideIndex] = new uint8_t[tcpPayloadSize];
				memcpy(connAnalysisInst->data[sideIndex],tcpLayer->getLayerPayload(),tcpPayloadSize);
			}
			// save the sequence for farther usage in next packets
			tcpReassemblyData->twoSides[sideIndex].prevSequence=sequence;

			// if TCP data size is 0 - nothing to do
			if (tcpPayloadSize == 0)
			{
				LOG_DEBUG("Payload length is 0, doing nothing");

				// handle case where this packet is FIN or RST
				if (isFinOrRst)
					handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, connAnalysis);

				return;
			}

			LOG_DEBUG("Found new data with expected sequence. Calling the callback");

			// update the sequence for this side to include TCP data from this packet
			tcpReassemblyData->twoSides[sideIndex].sequence += tcpPayloadSize;

			// if this is a SYN packet - add +1 to the sequence
			if (tcpLayer->getTcpHeader()->synFlag != 0)
				tcpReassemblyData->twoSides[sideIndex].sequence++;

			// send the data to the callback
			if (m_OnMessageReadyCallback != NULL)
			{
				TcpStreamData streamData(tcpLayer->getLayerPayload(), tcpPayloadSize, tcpReassemblyData->connData);
				streamData.setDeleteDataOnDestruction(false);
				m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
			}

			//while (checkOutOfOrderFragments(tcpReassemblyData, sideIndex)) {}

			// now that we've seen new data, go over the list of out-of-order packets and see if one or more of them fits now
			checkOutOfOrderFragments(tcpReassemblyData, sideIndex, false,connAnalysisInst);

			// handle case where this packet is FIN or RST
			if (isFinOrRst)
				handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, connAnalysis);

			// return - nothing else to do here
			return;
		}

		// this case means sequence size of the packet is higher than expected which means the packet is out-of-order or some packets were lost (missing data).
		// we don't know which of the 2 cases it is at this point so we just add this data to the out-of-order packet list
		else
		{
			// if TCP data size is 0 - nothing to do
			if (tcpPayloadSize == 0)
			{
				LOG_DEBUG("Payload length is 0, doing nothing");

				// handle case where this packet is FIN or RST
				if (isFinOrRst)
					handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, connAnalysis);

				return;
			}

			// create a new TcpFragment, copy the TCP data to it and add this packet to the the out-of-order packet list
			TcpFragment* newTcpFrag = new TcpFragment();
			newTcpFrag->data = new uint8_t[tcpPayloadSize];
			newTcpFrag->dataLength = tcpPayloadSize;
			newTcpFrag->sequence = sequence;
			newTcpFrag->count = count;
			memcpy(newTcpFrag->data, tcpLayer->getLayerPayload(), tcpPayloadSize);
			tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.pushBack(newTcpFrag);

			LOG_DEBUG("Found out-of-order packet and added a new TCP fragment with size %d to the out-of-order list of side %d", (int)tcpPayloadSize, sideIndex);

			// handle case where this packet is FIN or RST
			if (isFinOrRst)
			{
				handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, connAnalysis);
				return;
			}

		}
	}
	else
		// mark this connection as weired and skip the packet just go to the next one
		connAnalysisInst->weired = true;

}

void TcpReassembly::reassemblePacket(RawPacket* tcpRawData, std::map<uint32_t, connectionAnalysisStruct*> &connAnalysis)
{
	Packet parsedPacket(tcpRawData, false);
	reassemblePacket(parsedPacket,false,connAnalysis);
}

std::string TcpReassembly::prepareMissingDataMessage(uint32_t missingDataLen)
{
	std::stringstream missingDataTextStream;
	missingDataTextStream << "[" << missingDataLen << " bytes missing]";
	return missingDataTextStream.str();
}


void TcpReassembly::checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, int sideIndex, bool cleanWholeFragList, connectionAnalysisStruct* connAnalysisInst)
{


	bool foundSomething = false;

	do
	{
		LOG_DEBUG("Starting first iteration of checkOutOfOrderFragments - looking for fragments that match the current sequence or have smaller sequence");

		int index = 0;
		foundSomething = false;

		do
		{
			index = 0;
			foundSomething = false;

			// first fragment list iteration - go over the whole fragment list and see if can find fragments that match the current sequence
			// or have smaller sequence but have big enough payload to get new data
			while (index < (int)tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.size())
			{
				TcpFragment* curTcpFrag = tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.at(index);

				// if fragment sequence matches the current sequence
				if (curTcpFrag->sequence == tcpReassemblyData->twoSides[sideIndex].sequence)
				{
					// update the packet number
					connAnalysisInst->packetNumber[sideIndex] = curTcpFrag->count;

					// if this packet holds data save them for farther usage in next packets
					if (curTcpFrag->dataLength != 0)
					{
						connAnalysisInst->dataLength[sideIndex] = curTcpFrag->dataLength;
						connAnalysisInst->data[sideIndex] = new uint8_t[curTcpFrag->dataLength];
						memcpy(connAnalysisInst->data[sideIndex],curTcpFrag->data,curTcpFrag->dataLength);
					}


					// update sequence
					tcpReassemblyData->twoSides[sideIndex].sequence += curTcpFrag->dataLength;
					if (curTcpFrag->data != NULL)
					{
						LOG_DEBUG("Found an out-of-order packet matching to the current sequence with size %d on side %d. Pulling it out of the list and sending the data to the callback", (int)curTcpFrag->dataLength, sideIndex);

						// send new data to callback

						if (m_OnMessageReadyCallback != NULL)
						{
							TcpStreamData streamData(curTcpFrag->data, curTcpFrag->dataLength, tcpReassemblyData->connData);
							streamData.setDeleteDataOnDestruction(false);
							m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
						}

					}


					// remove fragment from list
					tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.erase(tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.begin() + index);
					
					// Save the sequence as the previous sequence
					tcpReassemblyData->twoSides[sideIndex].prevSequence= curTcpFrag->sequence;
					
					foundSomething = true;

					continue;
				}

				// if fragment sequence has lower sequence than the current sequence
				if (curTcpFrag->sequence < tcpReassemblyData->twoSides[sideIndex].sequence)
				{
					// extract the previous packet number
					int oldPacketNumber = connAnalysisInst->packetNumber[sideIndex];
					// update the packet number
					connAnalysisInst->packetNumber[sideIndex] = curTcpFrag->count;
					size_t dataLength;
					uint8_t* data;
					// extract the data of the previous packet
					if (connAnalysisInst->dataLength[sideIndex] != 0 && connAnalysisInst->data[sideIndex] != NULL)
					{
						dataLength = connAnalysisInst->dataLength[sideIndex];
						data = new uint8_t[dataLength];
						memcpy(data,connAnalysisInst->data[sideIndex],dataLength);
					}
					else
					{
						dataLength = 0;
						data = NULL;
					}

					// if this packet holds data save them for farther usage in next packets
					if (curTcpFrag->dataLength != 0)
					{
						connAnalysisInst->dataLength[sideIndex] = curTcpFrag->dataLength;
						connAnalysisInst->data[sideIndex] = new uint8_t[curTcpFrag->dataLength];
						memcpy(connAnalysisInst->data[sideIndex],curTcpFrag->data,curTcpFrag->dataLength);
					}

					// create a retransmission instance
					retransmission retransInst;
					// calculate the previous data packet number
					retransInst.oldPacketNumber = oldPacketNumber; 
					// save the current packet number
					retransInst.newPacketNumber = curTcpFrag->count; 
					
					
					if (data != NULL)
					{
						// calculate the data of the previous data packet 
						retransInst.oldDataLength = dataLength;
						retransInst.oldData = new uint8_t[dataLength];
						memcpy(retransInst.oldData,data,dataLength);
					
						// if their is new data calculate them
						if ( retransInst.oldDataLength != curTcpFrag->dataLength || memcmp(curTcpFrag->data,retransInst.oldData,curTcpFrag->dataLength) )
						{
							//  the offset of the new data
							retransInst.offset = curTcpFrag->sequence - tcpReassemblyData->twoSides[sideIndex].prevSequence;

							retransInst.transmissionWithNewData = true;
							retransInst.newDataLength = curTcpFrag->dataLength;
							retransInst.newData = new uint8_t[curTcpFrag->dataLength];
							memcpy(retransInst.newData,curTcpFrag->data,curTcpFrag->dataLength);
						}
					}
					else 
					{
						retransInst.oldDataLength = 0;
						retransInst.oldData = NULL;
						retransInst.newDataLength = 0;
						retransInst.newData = NULL;
					}


					// calculate the sequence after this packet to see if this TCP payload contains also new data
					uint32_t newSequence = curTcpFrag->sequence + curTcpFrag->dataLength;

					// save if the packet is a full or partial retransmission of the previous packet
					if (tcpReassemblyData->twoSides[sideIndex].prevSequence == curTcpFrag->sequence)
						retransInst.fullRetransmission=true;
					else
						retransInst.partialRetransmission=true;

					connAnalysisInst->retransmitted[sideIndex].push_back(retransInst) ; 


					// it has new data
					if (newSequence > tcpReassemblyData->twoSides[sideIndex].sequence)
					{
						// calculate the delta new data size
						uint32_t newLength = tcpReassemblyData->twoSides[sideIndex].sequence - curTcpFrag->sequence;

						LOG_DEBUG("Found a fragment in the out-of-order list which its sequence is lower than expected but its payload is long enough to contain new data. "
							"Calling the callback with the new data. Fragment size is %d on side %d, new data size is %d", (int)curTcpFrag->dataLength, sideIndex, (int)(curTcpFrag->dataLength - newLength));

						// update current sequence with the delta new data size
						tcpReassemblyData->twoSides[sideIndex].sequence += curTcpFrag->dataLength - newLength;

						// send only the new data to the callback
						if (m_OnMessageReadyCallback != NULL)
						{
							TcpStreamData streamData(curTcpFrag->data + newLength, curTcpFrag->dataLength - newLength, tcpReassemblyData->connData);
							streamData.setDeleteDataOnDestruction(false);
							m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
						}

						foundSomething = true;
					}
					else
					{
						LOG_DEBUG("Found a fragment in the out-of-order list which doesn't contain any new data, ignoring it. Fragment size is %d on side %d", (int)curTcpFrag->dataLength, sideIndex);
					}
					// Save the sequence as the previous sequence
					tcpReassemblyData->twoSides[sideIndex].prevSequence=curTcpFrag->sequence;
					// delete fragment from list
					tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.erase(tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.begin() + index);

					continue;
				}

				//if got to here it means the fragment has higher sequence than current sequence, increment index and continue
				index++;
			}

			// if managed to find new segment, do the search all over again
		} while (foundSomething);


		// if got here it means we're left only with fragments that have higher sequence than current sequence. This means out-of-order packets or
		// missing data. If we don't want to clear the frag list yet, assume it's out-of-order and return
		if (!cleanWholeFragList)
			return;

		LOG_DEBUG("Starting second  iteration of checkOutOfOrderFragments - handle missing data");

		// second fragment list iteration - now we're left only with fragments that have higher sequence than current sequence. This means missing data.
		// Search for the fragment with the closest sequence to the current one

		uint32_t closestSequence = 0xffffffff;
		int closestSequenceFragIndex = -1;
		index = 0;

		while (index < (int)tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.size())
		{
			// extract segment at current index
			TcpFragment* curTcpFrag = tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.at(index);

			// check if its sequence is closer than current closest sequence
			if (curTcpFrag->sequence < closestSequence)
			{
				closestSequence = curTcpFrag->sequence;
				closestSequenceFragIndex = index;
			}

			index++;
		}

		// this means fragment list is not empty at this stage
		if (closestSequenceFragIndex > -1)
		{
			// get the fragment with the closest sequence
			TcpFragment* curTcpFrag = tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.at(closestSequenceFragIndex);

			// calculate number of missing bytes
			uint32_t missingDataLen = curTcpFrag->sequence - tcpReassemblyData->twoSides[sideIndex].sequence;

			// update sequence
			tcpReassemblyData->twoSides[sideIndex].sequence = curTcpFrag->sequence + curTcpFrag->dataLength;
			if (curTcpFrag->data != NULL)
			{
				// send new data to callback
				if (m_OnMessageReadyCallback != NULL)
				{
					// prepare missing data text
					std::string missingDataTextStr = prepareMissingDataMessage(missingDataLen);

					// add missing data text to the data that will be sent to the callback. This means that the data will look something like:
					// "[xx bytes missing]<original_data>"
					size_t dataWithMissingDataTextLen = missingDataTextStr.length() + curTcpFrag->dataLength;
					uint8_t* dataWithMissingDataText = new uint8_t[dataWithMissingDataTextLen];
					memcpy(dataWithMissingDataText, missingDataTextStr.c_str(), missingDataTextStr.length());
					memcpy(dataWithMissingDataText + missingDataTextStr.length(), curTcpFrag->data, curTcpFrag->dataLength);

					//TcpStreamData streamData(curTcpFrag->data, curTcpFrag->dataLength, tcpReassemblyData->connData);
					//streamData.setDeleteDataOnDestruction(false);
					TcpStreamData streamData(dataWithMissingDataText, dataWithMissingDataTextLen, tcpReassemblyData->connData);
					m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);

					LOG_DEBUG("Found missing data on side %d: %d byte are missing. Sending the closest fragment which is in size %d + missing text message which size is %d",
						sideIndex, missingDataLen, (int)curTcpFrag->dataLength, (int)missingDataTextStr.length());
				}
			}

			// remove fragment from list
			tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.erase(tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.begin() + closestSequenceFragIndex);

			LOG_DEBUG("Calling checkOutOfOrderFragments again from the start");

			// call the method again from the start to do the whole search again (both iterations). 
			// the stop condition is when the list is empty (so closestSequenceFragIndex == -1)
			foundSomething = true;
		}

	} while (foundSomething);
}

void TcpReassembly::handleFinOrRst(TcpReassemblyData* tcpReassemblyData, int sideIndex, uint32_t flowKey, std::map<uint32_t, connectionAnalysisStruct*> &ConnAnalysis)
{
	// if this side already saw a FIN or RST packet, do nothing and return
	if (tcpReassemblyData->twoSides[sideIndex].gotFinOrRst)
		return;

	LOG_DEBUG("Handling FIN or RST packet on side %d", sideIndex);

	// set FIN/RST flag for this side
	tcpReassemblyData->twoSides[sideIndex].gotFinOrRst = true;
	//printf("%d\n", tcpReassemblyData->twoSides[sideIndex].isOverlaped );

	// check if the other side also sees FIN or RST packet. If so - close the flow. Otherwise - only clear the out-of-order packets for this side
	int otherSideIndex = 1 - sideIndex;

	connectionAnalysisStruct* connAnalysisInst=NULL;
	std::map<uint32_t, connectionAnalysisStruct*>::iterator connectionAnalysisIter = ConnAnalysis.find(flowKey);
	connAnalysisInst = connectionAnalysisIter->second;
	
	if (tcpReassemblyData->twoSides[otherSideIndex].gotFinOrRst)

		closeConnectionInternal(flowKey, TcpReassembly::TcpReassemblyConnectionClosedByFIN_RST, ConnAnalysis);
	else
		checkOutOfOrderFragments(tcpReassemblyData, sideIndex, true, connAnalysisInst);
}

void TcpReassembly::closeConnection(uint32_t flowKey, std::map<uint32_t, connectionAnalysisStruct*> &ConnAnalysis)
{
	closeConnectionInternal(flowKey, TcpReassembly::TcpReassemblyConnectionClosedManually, ConnAnalysis);
}

void TcpReassembly::closeConnectionInternal(uint32_t flowKey, ConnectionEndReason reason, std::map<uint32_t, connectionAnalysisStruct*> &ConnAnalysis)
{
	TcpReassemblyData* tcpReassemblyData = NULL;
	std::map<uint32_t, TcpReassemblyData*>::iterator iter = m_ConnectionList.find(flowKey);
	if (iter == m_ConnectionList.end())
	{
		LOG_ERROR("Cannot close flow with key 0x%X: cannot find flow", flowKey);
		return;
	}

	LOG_DEBUG("Closing connection with flow key 0x%X", flowKey);

	tcpReassemblyData = iter->second;

	connectionAnalysisStruct* connAnalysisInst=NULL;
	std::map<uint32_t, connectionAnalysisStruct*>::iterator connectionAnalysisIter = ConnAnalysis.find(flowKey);
	connAnalysisInst = connectionAnalysisIter->second;
	
	LOG_DEBUG("Calling checkOutOfOrderFragments on side 0");
	checkOutOfOrderFragments(tcpReassemblyData, 0, true, connAnalysisInst);

	LOG_DEBUG("Calling checkOutOfOrderFragments on side 1");
	checkOutOfOrderFragments(tcpReassemblyData, 1, true, connAnalysisInst);

	if (m_OnConnEnd != NULL)
		m_OnConnEnd(connAnalysisInst,tcpReassemblyData->connData, reason, m_UserCookie, m_cnxNumber, m_cnxNumberLength);

	delete tcpReassemblyData;
	delete connAnalysisInst;
	ConnAnalysis.erase(connectionAnalysisIter);
	m_ConnectionList.erase(iter);
	m_ClosedConnectionList[flowKey] = true;

	LOG_DEBUG("Connection with flow key 0x%X is closed", flowKey);
}

void TcpReassembly::closeAllConnections( std::map<uint32_t, connectionAnalysisStruct*> &ConnAnalysis )
{
	LOG_DEBUG("Closing all flows");

	while (!m_ConnectionList.empty())
	{
		TcpReassemblyData* tcpReassemblyData = m_ConnectionList.begin()->second;
		connectionAnalysisStruct* connAnalysisInst = ConnAnalysis.begin()->second;
		uint32_t flowKey = tcpReassemblyData->connData.flowKey;
		LOG_DEBUG("Closing connection with flow key 0x%X", flowKey);

		LOG_DEBUG("Calling checkOutOfOrderFragments on side 0");
		checkOutOfOrderFragments(tcpReassemblyData, 0, true, connAnalysisInst);

		LOG_DEBUG("Calling checkOutOfOrderFragments on side 1");
		checkOutOfOrderFragments(tcpReassemblyData, 1, true, connAnalysisInst);
		if (m_OnConnEnd != NULL)
			m_OnConnEnd(connAnalysisInst,tcpReassemblyData->connData, TcpReassemblyConnectionClosedManually, m_UserCookie, m_cnxNumber, m_cnxNumberLength);
		ConnAnalysis.erase(ConnAnalysis.begin());

		delete tcpReassemblyData;
		m_ConnectionList.erase(m_ConnectionList.begin());
		m_ClosedConnectionList[flowKey] = true;

		LOG_DEBUG("Connection with flow key 0x%X is closed", flowKey);
	}
	m_ConnectionInfo.clear();
	

}

const std::vector<ConnectionData>& TcpReassembly::getConnectionInformation() const
{
	return m_ConnectionInfo;
}

int TcpReassembly::isConnectionOpen(const ConnectionData& connection)
{
	if (m_ConnectionList.find(connection.flowKey) != m_ConnectionList.end())
		return 1;

	if (m_ClosedConnectionList.find(connection.flowKey) != m_ClosedConnectionList.end())
		return 0;

	return -1;
}

}
