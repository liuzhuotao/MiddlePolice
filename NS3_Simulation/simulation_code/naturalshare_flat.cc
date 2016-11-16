/*
 * NaturalShare policy VS. Flat rate attack
 */

#include <fstream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

//packet tag head files
#include "ns3/tag.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"

//head files
#include "ns3/point-to-point-layout-module.h"
#include "ns3/rtt-estimator.h"
#include "ns3/nstime.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/random-variable-stream.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/point-to-point-net-device.h"

#include <iostream>
#include <iomanip>
#include <map>
#include <fstream>
#include <ctime>
#include <locale>
#include <time.h>
#include <stdlib.h>

// Internet traffic
#include "ns3/tmix.h"
#include "ns3/tmix-helper.h"
#include "ns3/delaybox-net-device.h"
#include "ns3/tmix-topology.h"
#include "ns3/tmix-ns2-style-trace-helper.h"


using namespace ns3;

/*
 * Gloable Variable
 */

#define ARRAY_SIZE 1000

std::string attackerDataRate = "30Mbps";
std::string clientDataRate = "1Mbps";
double period = 2.0;
double duration = period / 1;
uint16_t port = 5001;
uint16_t attackerport = 5003;
uint16_t    mmtu = 1599;
std::ofstream queueFile ("queueLength.dat", std::ios::out);
//std::ofstream congestionUsageFile ("congestionUsage.dat", std::ios::out);
//std::ofstream normalUsageFile ("normalUsage.dat", std::ios::out);
std::ofstream droprateFile ("dropRate.dat", std::ios::out);
//std::ofstream rawdropFile ("rawDropRate.dat", std::ios::out);
Ptr<Node> router;
Ptr <PointToPointNetDevice> p2pDevice;
uint32_t    nLeaf = 4; 
uint32_t    nAttacker = 4; 
int size = nLeaf + nAttacker;
double detectPeriod = 0.0;
uint32_t lock = 0;
uint32_t dropArray[ARRAY_SIZE];
//uint32_t dropTag[5000];
uint32_t congWin[ARRAY_SIZE];
//uint32_t verifyWin[5000]; // representing the verified capabilities
//uint32_t tagWin[5000]; // representing the tagged packets
uint32_t receiveWin[ARRAY_SIZE]; // representing the received packets (usage)
uint16_t enableEarlyDrop = 1;
uint32_t bootStrap = 0;


// Used for measuring real time loss rate
uint32_t realtimePeriod = 0;
uint32_t realtimePacketFeedback = 50;
double realtimeLossRate = 0;
uint32_t realtimeDrop = 0;
double lossRateArray[ARRAY_SIZE];

// Used for crossing traffic
uint32_t nCrossing = 0;
std::ifstream cvectFileA;
std::ifstream cvectFileB;
Ptr<DelayBox> m_delayBox = CreateObject<DelayBox> ();


// parameters
double lossRateThreshold = 0.05;
double beta = 0.8;


// for fairshare
double total_capacity = 0;

// for recording the congestion window
std::ofstream windowFile ("natural_flat_window.data", std::ios::out);
std::ofstream lossRateFile ("natural_flat_LR.data", std::ios::out);



//=========================================================================//
//=========================Begin of TAG definition=========================//
//=========================================================================//
class MyTag : public Tag
{
public:
  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;
  virtual uint32_t GetSerializedSize (void) const;
  virtual void Serialize (TagBuffer i) const;
  virtual void Deserialize (TagBuffer i);
  virtual void Print (std::ostream &os) const;

  // these are our accessors to our tag structure
  void SetSimpleValue (uint32_t value);
  uint32_t GetSimpleValue (void) const;
private:
  uint32_t m_simpleValue;
};

TypeId 
MyTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::MyTag")
    .SetParent<Tag> ()
    .AddConstructor<MyTag> ()
    .AddAttribute ("SimpleValue",
                   "A simple value",
                   EmptyAttributeValue (),
                   MakeUintegerAccessor (&MyTag::GetSimpleValue),
                   MakeUintegerChecker<uint32_t> ())
  ;
  return tid;
}
TypeId 
MyTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
uint32_t 
MyTag::GetSerializedSize (void) const
{
  return 4;
}
void 
MyTag::Serialize (TagBuffer i) const
{
  i.WriteU32 (m_simpleValue);
}
void 
MyTag::Deserialize (TagBuffer i)
{
  m_simpleValue = i.ReadU32 ();
}
void 
MyTag::Print (std::ostream &os) const
{
  os << "v=" << (uint32_t)m_simpleValue;
}
void 
MyTag::SetSimpleValue (uint32_t value)
{
  m_simpleValue = value;
}
uint32_t 
MyTag::GetSimpleValue (void) const
{
  return m_simpleValue;
}


//=========================================================================//
//===============Beigining of Application definition=======================//
//=========================================================================//

class MyApp : public Application 
{
public:

  MyApp ();
  virtual ~MyApp();

  //void Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);
  void Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, DataRate dataRate);
  void SetTagValue(uint32_t value);
  void SetDataRate(DataRate rate);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  void ScheduleTx (void);
  void SendPacket (void);

  Ptr<Socket>     m_socket;
  Address         m_peer;
  uint32_t        m_packetSize;
  //uint32_t        m_nPackets;
  DataRate        m_dataRate;
  EventId         m_sendEvent;
  bool            m_running;
  //uint32_t        m_packetsSent;
  uint32_t         m_tagValue;
};

MyApp::MyApp ()
  : m_socket (0), 
    m_peer (), 
    m_packetSize (0), 
    //m_nPackets (0), 
    m_dataRate (0), 
    m_sendEvent (), 
    m_running (false), 
    //m_packetsSent (0)
    m_tagValue (0)
{
}

MyApp::~MyApp()
{
  m_socket = 0;
}

void
//MyApp::Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate)
MyApp::Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, DataRate dataRate)
{
  m_socket = socket;
  m_peer = address;
  m_packetSize = packetSize;
  //m_nPackets = nPackets;
  m_dataRate = dataRate;
}

void
MyApp::SetDataRate(DataRate rate)
{
  m_dataRate = rate;
}

void
MyApp::SetTagValue(uint32_t value)
{
  m_tagValue = value;
}

void
MyApp::StartApplication (void)
{
  m_running = true;
  //m_packetsSent = 0;
  m_socket->Bind ();
  m_socket->Connect (m_peer);
  SendPacket ();
}

void 
MyApp::StopApplication (void)
{
  m_running = false;

  if (m_sendEvent.IsRunning ())
    {
      Simulator::Cancel (m_sendEvent);
    }

  if (m_socket)
    {
      m_socket->Close ();
    }
}

void 
MyApp::SendPacket (void)
{
  //create the tags
  MyTag tag;
  tag.SetSimpleValue (m_tagValue);

  Ptr<Packet> packet = Create<Packet> (m_packetSize);
  packet -> AddPacketTag (tag);//add tags

  m_socket->Send (packet);

  //if (++m_packetsSent < m_nPackets)
    //{
      ScheduleTx ();
    //}
}

void 
MyApp::ScheduleTx (void)
{
  if (m_running)
    {
      Time tNext (Seconds (m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ())));
      m_sendEvent = Simulator::Schedule (tNext, &MyApp::SendPacket, this);
    }
}
//=========================================================================//
//===================End of Application definition=========================//
//=========================================================================//



//=========================================================================//
//===================Internet Traffic Trace: NOT COMPLETED=================//
//=========================================================================//
// Choice one: distribute all traces to all crossing node pairs 
void
//ReadAndAddCvecs(Ptr<TmixTopology> tmix, TmixTopology::InitiatorSide side, std::istream& cvecfile, double chance)
ReadAndAddCvecs(std::istream& cvecfile, Ptr<Node> initiatorNode, Ipv4Address initiatorAddress, 
	      Ptr<Node> acceptorNode, Ipv4Address acceptorAddress) {
  //const int cvecsPerPair = 10000;
  //TmixTopology::TmixNodePair pair = tmix->NewPair(side);
  //SetTmixPairOptions(pair);
  //int nPairs = 1;
  Ptr<TmixHelper> helper = Create<TmixHelper> (m_delayBox, initiatorNode, 
  initiatorAddress, acceptorNode, acceptorAddress);

  int nCvecs = 0;
  Tmix::ConnectionVector cvec;
  while (Tmix::ParseConnectionVector(cvecfile, cvec) && ++nCvecs < 10000) {
    //std::cout << "reading\n";
    helper->AddConnectionVector(cvec);
    /*
    if (UniformVariable().GetValue() < chance) {
      pair.helper->AddConnectionVector(cvec);
      if (++nCvecs >= cvecsPerPair)
	{
	  pair = tmix->NewPair(side);
	  SetTmixPairOptions(pair);
	  nCvecs = 0;
	  nPairs++;
	}
    }*/
  }
  //NS_LOG_INFO("Read a total of " << ((nPairs-1)*cvecsPerPair + nCvecs) << " cvecs, distributing them to " << nPairs << " node pairs.");
}



//=========================================================================//
//===================Callbacks: Scheduled events=========================//
//=========================================================================//
void measureDropRate (Ptr<FlowMonitor> flowmon, uint64_t start)
{
  std::map<FlowId, FlowMonitor::FlowStats> flowstat = flowmon -> GetFlowStats();
  for (std::map<FlowId, FlowMonitor::FlowStats>::iterator it=flowstat.begin(); it!=flowstat.end(); ++it){
    //pending
    /*
     * Catch attack flow
    if (it->second.timeFirstTxPacket == NanoSeconds (start - 1000000000)){
      std::cout << "catch \n";
    }
    */
  }
}

void attackFlow (PointToPointDumbbellHelper d, uint32_t nAttacker, double stopTime) 
{
  for (uint32_t i = d.RightCount () - nAttacker; i < d.RightCount(); ++i){
    Ptr<Socket> ns3Socket = Socket::CreateSocket (d.GetRight(i), UdpSocketFactory::GetTypeId ());

    Address sinkAddress (InetSocketAddress (d.GetLeftIpv4Address (i), attackerport));
    Ptr<MyApp> app = CreateObject<MyApp> ();
    uint32_t tagValue = i + 1; //take the least significant 8 bits
    app -> SetTagValue(tagValue);
    app->Setup (ns3Socket, sinkAddress, 1000, DataRate (attackerDataRate));
    d.GetRight(i) -> AddApplication (app);
    app->SetStartTime (Seconds (0.0));
    app->SetStopTime (Seconds (duration));
  }
}
//=========================================================================//
//=========================================================================//
//=========================================================================//



//=========================================================================//
//========================Add tracing source===============================//
//=========================================================================//


void clearArray(){
  for (uint32_t j = 0; j < nLeaf + nAttacker; ++j){
    //std::cout << "client no: " << j << "; arrived: "<< receiveWin[j] << "; drop rate: " << 1.0 * dropArray[j] / receiveWin[j] << std::endl;
    receiveWin[j] = 0;
    dropArray[j] = 0;
  }
  total_capacity = 0;
}


// the sloping probability for best effort packets
bool slopingProb(double lossRate) {
  if (lossRate > lossRateThreshold) {
    return true;
  } else {
    double dropP = 20.0 * lossRate;
    double randP = (double) rand()/RAND_MAX;
    if (dropP <= randP) { 
      return true;
    }
  }

  return false;
}



static void
PktArrival (Ptr<const Packet> p)
{
  Ptr<Packet> pktCopy = p->Copy ();
  //uint32_t totalNormal = nLeaf;
  //uint32_t totalAttacker = nAttacker;


  //Ptr<Queue> redQueue = p2pDevice -> GetQueue ();
  //queueFile << Simulator::Now().GetSeconds() << "\t" << redQueue->GetNPackets() << "\n";
  // flow table populating
  MyTag tag;
  if (pktCopy -> PeekPacketTag(tag)) {
    // update usage for each flow
    uint32_t index = tag.GetSimpleValue() - 1;
    receiveWin[index] += 1;

    // Almost realtime loss measurement
    if (++realtimePeriod == realtimePacketFeedback) {
      realtimeLossRate = 1.0 * realtimeDrop / realtimePeriod;
      //std::cout << "realtime loss: " << realtimeLossRate << std::endl;
      realtimePeriod = 0;
      realtimeDrop = 0;
    }

    // Best-effort handling
    // Adding crossing traffic of bottleneck, which is not policed by MiddlePolice (tag between nLeaf-nCrossing, nLeaf)
    if (enableEarlyDrop > 0) {
      //if (receiveWin[index] > congWin[index] && index > nLeaf-nCrossing && index <= nLeaf) { // best-effort
      if (receiveWin[index] > congWin[index]) { // best-effort packets
      	if ((realtimeLossRate > lossRateThreshold) || (lossRateArray[index] > lossRateThreshold)) {
      	//if (slopingProb(realtimeLossRate) || slopingProb(lossRateArray[index])) {
	  p2pDevice -> SetEarlyDrop(true);
	  realtimeDrop--;
	}
      } 
    }
  }   

  // larger time scale: per detection period
  if (Simulator::Now().GetSeconds() > detectPeriod) {
    std::cout << "detection period: " << bootStrap++ << std::endl;
    if (windowFile.is_open())
    {
      windowFile << Simulator::Now().GetSeconds() << " ";
    }
    if (lossRateFile.is_open()) lossRateFile << Simulator::Now().GetSeconds() << " ";

    for (uint32_t j = 0; j < nLeaf + nAttacker; ++j){

      double lossRate = receiveWin[j] > 0 ? 1.0 * dropArray[j] / receiveWin[j] : 0.0;

      if (receiveWin[j] > 5) {
	lossRateArray[j] = (1-beta) * lossRate + beta * lossRateArray[j];
      } else {
	lossRateArray[j] = beta * lossRateArray[j];
      }

      if (receiveWin[j] >= dropArray[j]) congWin[j] = (receiveWin[j] - dropArray[j]);
      else congWin[j] = 0;

      if (windowFile.is_open())
      {
	windowFile << congWin[j] << " ";
      }

      if (lossRateFile.is_open()) lossRateFile << lossRateArray[j] << " ";

      std::cout << "Client NO." << j << "; congestion window: " << congWin[j] << "; loss rate: " << lossRateArray[j] << "; receive window: " << receiveWin[j] << "; drop window: " << dropArray[j] << "; realtime loss: " <<realtimeLossRate << std::endl;

    }

    if (windowFile.is_open())
    {
      windowFile << "\n";
    }
    if (lossRateFile.is_open()) lossRateFile << "\n";


    // update for the next period
    detectPeriod += period;
    clearArray();
  }

}

static void
PktDrop (Ptr<const Packet> p) {
  realtimeDrop += 1;
  //std::cout << "Dropping count " << realtimeDrop << std::endl;
  MyTag tag;
  if (p -> PeekPacketTag(tag)) {
    dropArray[tag.GetSimpleValue() - 1] += 1;
  }
}

static void
PktDropOverflow (Ptr<const Packet> p) {
  std::cout << "Dropping for overflow" << std::endl;
}

//=========================================================================//
//=========================================================================//
//=========================================================================//


//===========================Main Function=============================//
int 
main (int argc, char *argv[])
{
  uint32_t    maxPackets = 250; // The queue buffer size
  uint32_t    modeBytes  = 0;
  double      minTh = 100;
  double      maxTh = 200;
  uint32_t    pktSize = 1000;
  double      stopTime = 2.5;

  std::string appDataRate = "1Mbps";
  //std::string queueType = "DropTail";
  std::string queueType = "RED";
  std::string bottleNeckLinkBw = "10Mbps";
  std::string bottleNeckLinkDelay = "200ms";
  std::string attackFlowType = "ns3::UdpSocketFactory";
  std::string mtu = "1599";

  //get the local time
  std::time_t t = std::time(NULL);
  char localTime[100];
  std::strftime(localTime, 100, "%c", std::localtime(&t));

  CommandLine cmd;
  cmd.AddValue ("nLeaf",     "Number of left and right side leaf nodes", nLeaf);
  cmd.AddValue ("enableEarlyDrop",     "enableEarlyDrop", enableEarlyDrop);
  cmd.AddValue ("attackerDataRate",     "attack data rate", attackerDataRate);
  cmd.AddValue ("clientDataRate",     "legitimate users data rate", clientDataRate);
  cmd.AddValue ("bottleNeckLinkBw",     "bottle neck link bandwidth", bottleNeckLinkBw);
  cmd.AddValue ("stopTime",     "Stopping time for simulation", stopTime);
  cmd.AddValue ("attackFlowType",     "Type of attacking flows", attackFlowType);
  cmd.AddValue ("nAttacker",     "Number of TCP attacking flows", nAttacker);
  cmd.AddValue ("maxPackets","Max Packets allowed in the queue", maxPackets);
  cmd.AddValue ("queueType", "Set Queue type to DropTail or RED", queueType);
  cmd.AddValue ("appDataRate", "Set OnOff App DataRate", appDataRate);
  cmd.AddValue ("modeBytes", "Set Queue mode to Packets <0> or bytes <1>", modeBytes);
  cmd.AddValue ("nCrossing", "The number of crossing traffic flows", nCrossing);

  cmd.AddValue ("redMinTh", "RED queue minimum threshold", minTh);
  cmd.AddValue ("redMaxTh", "RED queue maximum threshold", maxTh);
  cmd.Parse (argc,argv);

  if ((queueType != "RED") && (queueType != "DropTail"))
  {
    NS_ABORT_MSG ("Invalid queue type: Use --queueType=RED or --queueType=DropTail");
  }

  //configuration
  //Config::SetDefault ("ns3::OnOffApplication::PacketSize", UintegerValue (pktSize));
  Config::SetDefault ("ns3::TcpL4Protocol::SocketType", StringValue ("ns3::TcpNewReno"));
  //Config::SetDefault ("ns3::OnOffApplication::DataRate", StringValue (appDataRate));

  if (modeBytes)
    {
      Config::SetDefault ("ns3::DropTailQueue::Mode", StringValue ("QUEUE_MODE_PACKETS"));
      Config::SetDefault ("ns3::DropTailQueue::MaxPackets", UintegerValue (maxPackets));
      Config::SetDefault ("ns3::RedQueue::Mode", StringValue ("QUEUE_MODE_PACKETS"));
      Config::SetDefault ("ns3::RedQueue::QueueLimit", UintegerValue (maxPackets));
    }
  else 
    {
      Config::SetDefault ("ns3::DropTailQueue::Mode", StringValue ("QUEUE_MODE_BYTES"));
      Config::SetDefault ("ns3::DropTailQueue::MaxBytes", UintegerValue (maxPackets * pktSize));
      Config::SetDefault ("ns3::RedQueue::Mode", StringValue ("QUEUE_MODE_BYTES"));
      Config::SetDefault ("ns3::RedQueue::QueueLimit", UintegerValue (maxPackets * pktSize));
      minTh *= pktSize; 
      maxTh *= pktSize;
    }

  //===================Create network topology===========================//
  // Need to create three links for this topo
  // 1. The connection between left nodes and left router
  // 2. The connection between right nodes and right router
  // 3. The connection between two routers
  PointToPointHelper bottleNeckLink;
  bottleNeckLink.SetDeviceAttribute("DataRate", StringValue (bottleNeckLinkBw));
  bottleNeckLink.SetDeviceAttribute("Mtu", StringValue (mtu));
  bottleNeckLink.SetChannelAttribute("Delay", StringValue (bottleNeckLinkDelay));
  
  if (queueType == "RED")
  {
    bottleNeckLink.SetQueue ("ns3::RedQueue",
			     "MinTh", DoubleValue (minTh),
			     "MaxTh", DoubleValue (maxTh),
			     "LinkBandwidth", StringValue (bottleNeckLinkBw),
			     "LinkDelay", StringValue (bottleNeckLinkDelay));
  }

  //leaf helper: 
  PointToPointHelper pointToPointLeaf;
  pointToPointLeaf.SetDeviceAttribute("DataRate", StringValue ("100000Mbps"));
  pointToPointLeaf.SetChannelAttribute("Delay", StringValue ("1ms"));

  // Dumbbell constructor: nLeaf normal flows and nAttacker attack flows
  PointToPointDumbbellHelper d (nLeaf + nAttacker, pointToPointLeaf,
                                nLeaf + nAttacker, pointToPointLeaf,
                                bottleNeckLink);

  // Install Stack to the whole nodes 
  InternetStackHelper stack;
  d.InstallStack (stack);

  // Assign IP Addresses
  // Three sets of address: the left, the right and the router
  d.AssignIpv4Addresses (Ipv4AddressHelper ("10.1.0.0", "255.255.255.252"),
                         Ipv4AddressHelper ("11.1.0.0", "255.255.255.252"),
                         Ipv4AddressHelper ("12.1.0.0", "255.255.255.252"));

  // obtain the p2p devices 
  //===================End of Creating Network Topology===================//
  

  //==========================================================================//
  //===================Config the LEFT side nodes: sink or receiver===========//
  //==========================================================================//
  
  // return the address of that endpoint
  Address sinkLocalAddress (InetSocketAddress (Ipv4Address::GetAny (), port));
  Address attackerSinkLocalAddress (InetSocketAddress (Ipv4Address::GetAny (), attackerport));

  // create the package sink application, which means that the endpoint will receive packets using certain protocols
  PacketSinkHelper packetSinkHelper ("ns3::TcpSocketFactory", sinkLocalAddress);
  PacketSinkHelper crossSinkHelper ("ns3::TcpSocketFactory", sinkLocalAddress);
  PacketSinkHelper attackerPacketSinkHelper (attackFlowType, attackerSinkLocalAddress);


  // Create the normal TCP flows sink applications 
  ApplicationContainer sinkApps; 
  //for (uint32_t i = 0; i < d.LeftCount () - nAttacker; ++i)
  for (uint32_t i = 0; i < d.LeftCount () - nAttacker - nCrossing; ++i)
  {
    // packetSinkHelper.Install (node): install the sink app on this node 
    // sinkApps.add (app): add one single application to the container
    sinkApps.Add (packetSinkHelper.Install (d.GetLeft (i)));
  }


  // Create the Internet traffic application
  ApplicationContainer internetTrafficApps;
  for (uint32_t i = d.LeftCount () - nAttacker - nCrossing; i < d.LeftCount() - nAttacker; ++i)
  {
    // Realistic Internet traffic 
    internetTrafficApps.Add (crossSinkHelper.Install (d.GetLeft (i)));
  }

  // Create the attack flow sink application
  ApplicationContainer attackerSinkApps; 
  for (uint32_t j = d.LeftCount () - nAttacker; j < d.LeftCount(); ++j)
  {
    attackerSinkApps.Add (attackerPacketSinkHelper.Install (d.GetLeft (j)));
  }

  // Arrange all application in the container to start and stop
  sinkApps.Start (Seconds (0.0));
  sinkApps.Stop (Seconds (stopTime));
  attackerSinkApps.Start (Seconds (0.0));
  attackerSinkApps.Stop (Seconds (stopTime));

  // add for the internet traffic
  internetTrafficApps.Start(Seconds(0.0));
  internetTrafficApps.Stop(Seconds(stopTime));
  
  
  //==========================================================================//
  //======================End of sink applications============================//
  //===========================================================================//
  


  //==========================================================================//
  //================Creating the normal client applications===================//
  //==========================================================================//
  for (uint32_t i = 0; i < d.RightCount () - nAttacker - nCrossing; ++i){
    Ptr<Socket> ns3Socket = Socket::CreateSocket (d.GetRight(i), TcpSocketFactory::GetTypeId ());

    Address sinkAddress (InetSocketAddress (d.GetLeftIpv4Address (i), port));
    Ptr<MyApp> app = CreateObject<MyApp> ();
    uint32_t tagValue = i + 1; //take the least significant 8 bits
    app -> SetTagValue(tagValue);
    app -> Setup (ns3Socket, sinkAddress, 1000, DataRate (clientDataRate));
    d.GetRight(i) -> AddApplication (app);
    app->SetStartTime (Seconds (0));
    app->SetStopTime (Seconds (stopTime));
  }
  //==========================================================================//
  //==================End of normal client applications=======================//
  //==========================================================================//
  

  //==========================================================================//
  //======================Creating crossing traffic===========================//
  //==========================================================================//
  cvectFileA.open("scratch/outbound.ns");
  cvectFileB.open("scratch/inbound.ns");
  for (uint32_t i = d.RightCount () - nAttacker - nCrossing; i < d.RightCount() - nAttacker; ++i){
    //ReadAndAddCvecs(cvectFileA, d.GetRight(i), d.GetRightIpv4Address(i), d.GetLeft(i), d.GetLeftIpv4Address(i));
    //ReadAndAddCvecs(cvectFileB, d.GetLeft(i), d.GetLeftIpv4Address(i), d.GetRight(i), d.GetRightIpv4Address(i));
  }
  //==========================================================================//
  //======================End crossing traffic===========================//
  //==========================================================================//
  
  

  //==========================================================================//
  //==================End of normal client applications=======================//
  //==========================================================================//
  

  //========================flow monitor======================================//
  
  Ptr<FlowMonitor> flowmon;
  FlowMonitorHelper flowmonHelper;
  flowmon = flowmonHelper.InstallAll ();
  flowmon -> Start (Seconds (0.0));
  flowmon -> Stop (Seconds (stopTime));

  //==========================================================================//


  //==========================================================================//
  //================Creating the attack client applications===================//
  //==========================================================================//
  double start = 0.1;
  for (; start < stopTime; start += period){
    //Simulator::Schedule(Seconds (start), &measureDropRate, flowmon, start);
    //Simulator::Schedule(Seconds (0.0), &attackFlow, d, nAttacker, stopTime);
    Simulator::Schedule(Seconds (start), &attackFlow, d, nAttacker, stopTime);
  }

  for (uint32_t j = 0; j < nLeaf + nAttacker; ++j){
    dropArray[j] = 0;
    congWin[j] = 0;
    receiveWin[j] = 0;
    lossRateArray[j] = 0;
  }
  //==========================================================================//
  //======================End of attacking applications=======================//
  //==========================================================================//


  //=============================Trace source============================//
  router = d.GetRight();
  Ptr<Node> rightRouter = d.GetRight();
  //std::cout << "number of devices: " << rightRouter->GetNDevices() << std::endl;
  for (uint32_t i = 0; i < rightRouter->GetNDevices(); ++i)
  {
    // Find the bottleneck device (p2p device)
    if ((rightRouter->GetDevice(i)->GetMtu()) == mmtu) {
      bottleNeckLink.EnablePcap ("router", rightRouter->GetDevice(i));
      rightRouter -> GetDevice(i) -> TraceConnectWithoutContext ("MacTx", MakeCallback (&PktArrival));
      rightRouter -> GetDevice(i) -> TraceConnectWithoutContext ("MacTxDrop", MakeCallback (&PktDrop));
      rightRouter -> GetDevice(i) -> TraceConnectWithoutContext ("PhyRxDrop", MakeCallback (&PktDropOverflow));
      p2pDevice = DynamicCast <PointToPointNetDevice> (router->GetDevice(i));
    }
  }
  //===========================================================================//


  // Routing table
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  std::cout << "Running the simulation" << std::endl;
  // The last event scheduled by the simulator
  Simulator::Stop (Seconds (stopTime));

  Simulator::Run ();

  // Calculating the sending rate
  // Legitimate flows
  double clientCounter = 0;
  double clientCounterSquare = 0;
  double totalCounter = 0;
  double totalCounterSquare = 0;

  for (uint32_t i = 0; i < sinkApps.GetN (); i++)
  {
    if (i < nLeaf - nCrossing) {
      Ptr <Application> app = sinkApps.Get (i);
      // PacketSink: receive and consume the traffic generated to the IP address and port
      Ptr <PacketSink> pktSink = DynamicCast <PacketSink> (app);

      // GetTotalRx: total bytes received in a sink app
      double bytes = 1.0 * pktSink->GetTotalRx () * 8 / 1000000;
      totalCounter += bytes;
      clientCounter += bytes;
      clientCounterSquare += (bytes * bytes);
      totalCounterSquare += (bytes * bytes);
    }
  }

  //Attack flows
  double attackerCounter = 0;
  double attackerCounterSquare = 0;
  for (uint32_t j = 0 ; j < attackerSinkApps.GetN (); j++)
  {
    Ptr <Application> app = attackerSinkApps.Get (j);
    // PacketSink: receive and consume the traffic generated to the IP address and port
    Ptr <PacketSink> pktSink = DynamicCast <PacketSink> (app);

    // GetTotalRx: total bytes received in a sink app
    double bytes = 1.0 * pktSink->GetTotalRx () * 8 / 1000000;
    attackerCounter += bytes;
    totalCounter += bytes;
    totalCounterSquare += (bytes * bytes);
    attackerCounterSquare += (bytes * bytes);
  }


  double normalAverageRate = nLeaf == 0 ? 0 : clientCounter / Simulator::Now().GetSeconds() / (nLeaf-nCrossing);
  double client_index = clientCounter * clientCounter / clientCounterSquare / nLeaf;
  double attackerAverageRate = nAttacker == 0 ? 0 : attackerCounter / Simulator::Now().GetSeconds() / nAttacker;
  double total_index = totalCounter * totalCounter / totalCounterSquare / nLeaf;
  
  //output to a file
  std::ofstream outputFile ("samerate", std::ios::out | std::ios::app);
  //std::ofstream outputFile ("output", std::ios::out | std::ios::app);
  //std::ofstream outputFile ("sstf", std::ios::out | std::ios::app);
  if (outputFile.is_open())
  {
    outputFile << "==============================================================="
	       << "\nNaturalShare with flat rate: "
	       << "\nRun simulation at: " << localTime 
	       << "\nSimulation duration: " << stopTime
	       //<< "\nAttack Flow Type: " << attackFlowType
               << "\nBottleneck link bandwidth: " << bottleNeckLinkBw
               << "\nAttacker data rate: " << attackerDataRate
               << "\nLegitimate data rate: " << clientDataRate
	       << "\nEnable early drop " << enableEarlyDrop 
	       << "\nNumber of attackers: " << nAttacker 
	       << "\nNumber of normal users: " << nLeaf - nCrossing
	       << "\nNumber of crossing users: " << nCrossing
	       << "\nQueue Type: " << queueType 
	       << "\nAttack period: " << period << ", attack duration: " << duration 
	       << "\nLoss rate threshold: " << lossRateThreshold
	       //<< "\nAttack Rate: " << attackerDataRate  
	       //<< "\nSimulation Time: "
	       //<< Simulator::Now ().GetSeconds () 
	       //<< "\nNormal Flows Received Bytes: "
	       //<< totalRxBytesCounter 
	       << "\nNormal Averaged Flows Rate: " 
	       << normalAverageRate << " Mbps"  
	       << "\nAttack Averaged Flow Rate: "  
	       << attackerAverageRate << " Mbps"  
	       << "\nClient fairness index: "  
	       << client_index 
	       << "\nTotal fairness index: "  
	       << total_index 
	       << "\n==============================================================\n";

    outputFile.close();
    //outfile.close();
  }
  else{
    std::cout << "Open File error" << std::endl;
  } 

  //flow monitor output
  flowmon->SerializeToXmlFile ("red.flowmon", false, false);
  
  // stat standard output

  std::cout << "Destroying the simulation" << std::endl;
  Simulator::Destroy ();
  return 0;
}

