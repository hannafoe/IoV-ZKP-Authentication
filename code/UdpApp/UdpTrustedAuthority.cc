//
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
// Copyright (C) 2004,2011 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//
#include <iostream>
#include <cstdint>
#include <vector>
#include <random>
#include <bitset>
#include <cmath>
#include <cstdlib>

//#include "openssl/obj_mac.h"
//#include "openssl/ec.h"
//#include "openssl/ecdh.h"
//#include "ecdh_ED25519.h"

#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/applications/udpapp/UdpTrustedAuthority.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/FragmentationTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"



//I have rewritten UdpTrustedAuthority taking UdpBasicApp from INET as template to represent 
//the class of the Trusted Authority in the ZAMA protocol

namespace inet {

Define_Module(UdpTrustedAuthority);

UdpTrustedAuthority::~UdpTrustedAuthority()
{
    cancelAndDelete(selfMsg);
}

void UdpTrustedAuthority::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        numSent = 0;
        numReceived = 0;
        WATCH(numSent);
        WATCH(numReceived);

        localPort = par("localPort");
        destPort = par("destPort");
        startTime = par("startTime");
        stopTime = par("stopTime");
        packetName = par("packetName");
        dontFragment = par("dontFragment");
        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new cMessage("sendTimer");
        start_registration();
    }
}

void UdpTrustedAuthority::start_registration()
{
    EV_INFO << "******Start registration process******" << endl;
    //Can send to RSU bcs it is initialized before, but not yet to VU

    //Initialize these variables in header file later, for global use in this file

    //initialize security parameters b,t,l,s
    //Have to be careful to not get integer overflow, so keep security parameters small for now
    s = 2;
    b = (uint64_t)pow(2,2);
    t = 2;
    l = 2;

    //initialise large composite number n
    uint64_t p = getBigPrime();//227;//getBigPrime();
    uint64_t q = getBigPrime();//179;//getBigPrime();
    n = p*q; //large composite number

    //generate elliptic curve parameters of Authentication Server (AS),
    //including public key PK_h and private key k_H of AS
    //class LIBCRYPTO_API EC_GROUP{
    //};
    //EC_GROUP *curve;
    //EC_GROUP LIBCRYPTO_API EC_GROUP_new_by_curve_name(int nid);
    //curve = EC_GROUP_new_by_curve_name(NID_secp224r1);

    //initialise ideal collision resistant hash function H

    //select g_1, g_2, h_1, h_2 in mult. group Z_n
    //selection in this way allows for order of g to be (p-1)(q-1)/4 = ca. n/4
    //unless r,r-1,r+1 happens to not be relatively prime to n
    //which happens with probability< 3/p+3/q = negligible
    g_1 = modPower(uint64_t(intuniform(2,n-2)),2,n);
    g_2 = modPower(uint64_t(intuniform(2,n-2)),2,n);
    h_1 = modPower(uint64_t(intuniform(2,n-2)),2,n);
    h_2 = modPower(uint64_t(intuniform(2,n-2)),2,n);

    //randomly select parameters r_1, r_2, x
    //r_1, r_2 can be negative so signed integer instead of unsigned
    r_1 = uint64_t(intuniform(pow(-2,s)*n+1,pow(2,s)*n+1));
    r_2 = uint64_t(intuniform(pow(-2,s)*n+1,pow(2,s)*n+1));
    x = uint64_t(intuniform(0,b));

    //compute commitments E, F
    //handle the case that either E or F is in range (0,1)
    //have to compute inverse mod n with Extended Euclidean Algorithm (EEA)
    uint64_t modhpowr1,modhpowr2;
    if (r_1<0){
        //change sign
        r_1 = -r_1;
        uint64_t modinv = modPower(h_1,r_1,n);
        modhpowr1 = modInverse(modinv, n);
    }else{
        modhpowr1 = modPower(h_1,r_1,n);
    }
    if (r_2<0){
        //change sign
        r_2 = -r_2;
        uint64_t modinv = modPower(h_1,r_1,n);
        modhpowr2 = modInverse(modinv, n);
    }else{
        modhpowr2 = modPower(h_1,r_1,n);
    }
    uint64_t modgpowx1 = modPower(g_1,x,n);
    uint64_t modgpowx2 = modPower(g_2,x,n);
    E = mulmod(modgpowx1,modhpowr1,n);
    F = mulmod(modgpowx2,modhpowr2, n);

    //select xi_1, xi_2 in Z_n
    xi_1 = modPower(uint64_t(intuniform(2,n-2)),2,n);
    xi_2 = modPower(uint64_t(intuniform(2,n-2)),2,n);

    //compute u,v,h as public key PK_U of VU
    u = modPower(g_1,xi_2,MAX_PRIME64);
    v = modPower(g_1,xi_1,MAX_PRIME64);
    h = modPower(g_1,(xi_1*xi_2),MAX_PRIME64);
    EV_INFO << "*****xi_1,xi_2,u,v,h " <<xi_1<<" "<<xi_2<<" "<<u<<" "<<v<<" "<<h << endl;


    //Initialize revocation list RL and secret database DB
    //Store (K_i, VID) for vehicles (data format)
    //initialized in header file

    //Rest of registration process must be initiated when VU are initiated...
}

void UdpTrustedAuthority::finish()
{
    recordScalar("packets sent", numSent);
    recordScalar("packets received", numReceived);
    ApplicationBase::finish();
}

void UdpTrustedAuthority::setSocketOptions()
{
    int timeToLive = par("timeToLive");
    if (timeToLive != -1)
        socket.setTimeToLive(timeToLive);

    int dscp = par("dscp");
    if (dscp != -1)
        socket.setDscp(dscp);

    int tos = par("tos");
    if (tos != -1)
        socket.setTos(tos);

    const char *multicastInterface = par("multicastInterface");
    if (multicastInterface[0]) {
        IInterfaceTable *ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        InterfaceEntry *ie = ift->findInterfaceByName(multicastInterface);
        if (!ie)
            throw cRuntimeError("Wrong multicastInterface setting: no interface named \"%s\"", multicastInterface);
        socket.setMulticastOutputInterface(ie->getInterfaceId());
    }

    bool receiveBroadcast = par("receiveBroadcast");
    if (receiveBroadcast)
        socket.setBroadcast(true);

    bool joinLocalMulticastGroups = par("joinLocalMulticastGroups");
    if (joinLocalMulticastGroups) {
        MulticastGroupList mgl = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this)->collectMulticastGroups();
        socket.joinLocalMulticastGroups(mgl);
    }
    socket.setCallback(this);
}

L3Address UdpTrustedAuthority::chooseDestAddr()
{
    int k = intrand(destAddresses.size());
    if (destAddresses[k].isUnspecified() || destAddresses[k].isLinkLocal()) {
        L3AddressResolver().tryResolve(destAddressStr[k].c_str(), destAddresses[k]);
    }
    return destAddresses[k];
}

void UdpTrustedAuthority::sendPacket()
{
    std::ostringstream str;
    str << packetName << "-" << numSent;
    Packet *packet = new Packet(str.str().c_str());
    if(dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<ApplicationPacket>();
    payload->setChunkLength(B(par("messageLength")));
    payload->setSequenceNumber(numSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = chooseDestAddr();
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numSent++;
}
void UdpTrustedAuthority::sendString(std::string name,std::string data, L3Address destAddr,std::string destAddrStr)
{
    if (destAddr.isUnspecified() || destAddr.isLinkLocal()) {
        L3AddressResolver().tryResolve(destAddrStr.c_str(), destAddr);
    }

    std::ostringstream str;
    str << name;
    Packet *packet = new Packet(str.str().c_str());
    if(dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<ApplicationPacket>();
    payload->setSequenceNumber(numSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    payload->setData(data.c_str());
    if(payload->getChunkLength()<B(par("messageLength"))){
        payload->setChunkLength(B(par("messageLength")));
    }
    std::ostringstream srcAdd;
    auto srcAddress = L3AddressResolver().addressOf(getModuleByPath(getParentModule()->getFullPath().c_str()), 27);
    srcAdd<<srcAddress;
    payload->setSrcAddress(srcAdd.str().c_str());
    payload->setDestAddress(destAddrStr.c_str());
    packet->insertAtBack(payload);
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
}


void UdpTrustedAuthority::processStart()
{
    socket.setOutputGate(gate("socketOut"));
    const char *localAddress = par("localAddress");
    socket.bind(*localAddress ? L3AddressResolver().resolve(localAddress) : L3Address(), localPort);
    EV_INFO << "******Socket bind ******" << localPort << endl;
    setSocketOptions();

    const char *destAddrs = par("destAddresses");
    cStringTokenizer tokenizer(destAddrs);
    const char *token;

    while ((token = tokenizer.nextToken()) != nullptr) {
        destAddressStr.push_back(token);
        L3Address result;
        L3AddressResolver().tryResolve(token, result);
        if (result.isUnspecified())
            EV_ERROR << "cannot resolve destination address: " << token << endl;
        destAddresses.push_back(result);
        EV_INFO << "******Start process, destination addresses: ******" << result << endl;
    }

    //Send E,F to AS
    //Then send over E and F
    std::string str = "E: "+ std::to_string(E) + " F: " + std::to_string(F)+" "+std::to_string(h_1)+" "+std::to_string(h_2)+
            " "+std::to_string(g_1)+" "+std::to_string(g_2)+" "+std::to_string(n);;
    std::string name = "Commitments E and F";
    L3Address destAddress = destAddresses[0];
    std::string destAddrStr = destAddressStr[0];
    sendString(name,str,destAddress,destAddrStr);

    if (!destAddresses.empty()) {
        //Only send messages at request, so do not send any messages here
        //selfMsg->setKind(SEND);
        //processSend();
    }
    else {
        if (stopTime >= SIMTIME_ZERO) {
            selfMsg->setKind(STOP);
            scheduleAt(stopTime, selfMsg);
            EV_INFO << "******processStart: stopTime >= SIMTIME_ZERO******" << endl;
        }
    }
}

void UdpTrustedAuthority::processSend()
{
    sendPacket();
    simtime_t d = simTime() + par("sendInterval");
    if (stopTime < SIMTIME_ZERO || d < stopTime) {
        selfMsg->setKind(SEND);
        scheduleAt(d, selfMsg);
    }
    else {
        EV_INFO << "******processSend: stopTime < SIMTIME_ZERO || d < stopTime******" << endl;
        selfMsg->setKind(STOP);
        scheduleAt(stopTime, selfMsg);
    }
}

void UdpTrustedAuthority::processStop()
{
    socket.close();
}

void UdpTrustedAuthority::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        ASSERT(msg == selfMsg);
        switch (selfMsg->getKind()) {
            case START:
                processStart();
                break;

            case SEND:
                processSend();
                break;

            case STOP:
                processStop();
                break;

            default:
                throw cRuntimeError("Invalid kind %d in self message", (int)selfMsg->getKind());
        }
    }
    else
        socket.processMessage(msg);
}

void UdpTrustedAuthority::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    // process incoming packet
    processPacket(packet);
}

void UdpTrustedAuthority::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void UdpTrustedAuthority::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

void UdpTrustedAuthority::refreshDisplay() const
{
    ApplicationBase::refreshDisplay();

    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);
}

void UdpTrustedAuthority::processPacket(Packet *pk)
{
    emit(packetReceivedSignal, pk);
    std::string ReceivedPacket = UdpSocket::getReceivedPacketInfo(pk);
    EV_INFO << "*****Received packet: " << ReceivedPacket << endl;
    //std::string s1("RSUDemandPacket");
    std::string s2("SourceAddress");
    std::string s1("in RL");
    if(ReceivedPacket.find(s2)!=std::string::npos){


        //For the ith user, TA randomly selects secret key K_i in the element of Z_n
        //After that TA assigns {r_1,r_2,x,K_i,PK_U} to VU
        //In the DB, VU's identity information is stored in the form of {K_i, VID}
        //First select secret key K_i
        K_i = modPower(uint64_t(intuniform(2,n-2)),2,n);
        //Get UID out of ReceivedPacket string

        const auto& payload  = pk->peekData<ApplicationPacket>();
        auto receivedData = payload->getData();
        EV_INFO << "Received data: " << receivedData<< endl;
        cStringTokenizer tokenizer(receivedData);
        const char *token;
        token = tokenizer.nextToken();
        token = tokenizer.nextToken();
        std::istringstream out1(token);
        std::string UID;
        out1>>UID;
        L3Address vehicle;
        EV_INFO << "UID: " << UID <<endl;
        //save K_i with UID in database
        L3Address result;
        L3AddressResolver().tryResolve(UID.c_str(), vehicle);
        DB.insert({K_i, vehicle});
        //Actually a,b,t,l,s,n,g_1,g_2,h_1,h_2 are also needed

        //send over r_1, r_2, x, K_i, u,v,h
        std::string packetName = "Authorization Info";
        //u,v,h should be individual to all vehicle users
        std::string str = std::to_string(r_1)+" "+ std::to_string(r_2)+" "+std::to_string(x)+
                            " "+std::to_string(K_i)+" "+std::to_string(u)+" "+std::to_string(v)+
                            " "+std::to_string(h)+" "+std::to_string(h_1)+" "+std::to_string(h_2)+
                            " "+std::to_string(g_1)+" "+std::to_string(g_2)+" "+std::to_string(n);
        sendString(packetName,str,vehicle,UID);

    }if(ReceivedPacket.find(s1)!=std::string::npos){
        const auto& payload  = pk->peekData<ApplicationPacket>();
        auto receivedData = payload->getData();
        EV_INFO << "Received data: " << receivedData<< endl;
        cStringTokenizer tokenizer(receivedData);
        const char *token;
        token = tokenizer.nextToken();
        std::istringstream out6(token);
        out6>>T_1;
        token = tokenizer.nextToken();
        std::istringstream out7(token);
        out7>>T_2;
        token = tokenizer.nextToken();
        std::istringstream out8(token);
        out8>>T_3;
        EV_INFO << "*****Received T_1,T_2,T_3: " <<T_1<<" " <<T_2<<" "<<T_3 <<endl;
        //TA should obtain K_i according to following calculation
        //with xi_1, xi_2
        //K_i = T_1**xi_1*T_2**xi_2/T_3
        //Acc 1/K_i = T_1**xi_1*T_2**xi_2/T_3 by calculation
        //Can't just divide, but have to multiply with inverse
        uint64_t modInvT_3 = uint64_t(modInverse(int64_t(T_3), int64_t(MAX_PRIME64)));
        EV_INFO << "*****Calculated modular inverse T3: " <<modInvT_3<<endl;
        EV_INFO<<"modPower(T_1,xi_1,MAX_PRIME64): "<<powMod(T_1,xi_1,MAX_PRIME64)<<" "<<modPower(T_1,xi_1,MAX_PRIME64)<<endl;
        EV_INFO<<"modPower(T_2,xi_2,MAX_PRIME64): "<<powMod(T_2,xi_2,MAX_PRIME64)<<" "<<modPower(T_2,xi_2,MAX_PRIME64)<<endl;
        EV_INFO<<"mulmod(modPower(T_1,xi_1,MAX_PRIME64),modPower(T_2,xi_2,MAX_PRIME64),MAX_PRIME64): "<<mulmod(powMod(T_1,xi_1,MAX_PRIME64),powMod(T_2,xi_2,MAX_PRIME64),MAX_PRIME64)<<endl;

        for(auto it = DB.cbegin(); it != DB.cend(); ++it)
        {
            EV_INFO << it->first << " " << it->second<<endl;
        }
        //only numbers coprime to UINT64_MAX have a modular inverse
        //This does not work since UINT64_MAX is not a prime
        //biggest 32 bit prime: 2147483647, since have to convert to INT64 instead of UINT64 for euclidean algorithm
        //
        uint64_t inv_K_1 = mulmod(mulmod(powMod(T_1,xi_1,MAX_PRIME64),powMod(T_2,xi_2,MAX_PRIME64),MAX_PRIME64),modInvT_3,MAX_PRIME64);
        EV_INFO << "one divided by K_1 " <<inv_K_1<<endl;
        uint64_t K_1 = uint64_t(modInverse(int64_t(inv_K_1),int64_t(MAX_PRIME64)));
        //EV_INFO << "*****Calculated K_1: " <<K_1<<endl;
        //uint64_t K_1 =1;
        EV_INFO << "*****Calculated K_1: " <<K_1<<endl;
        //Check if calculated K_1 can be found in DB

        if(DB.find(K_1)==DB.end()){
            //not found error
            EV_ERROR<<"Couldn't find K_1: "<<K_1<<" in database."<<endl;
        }else{
            //found key in DB, valid vehicle ID
            EV_INFO<<"Found K_1: "<<K_1<<" in database"<<endl;
        }
        //Check if calculated K_1 can be found in RL
        std::string data;
        if(RL.find(K_1)==RL.end()){
            //not found error
            EV_INFO<<"Didn't find K_1: "<<K_1<<" in Revocation List. All good!!"<<endl;
            data = "success";
        }else{
            //found key in DB, valid vehicle ID
            EV_INFO<<"Found K_1: "<<K_1<<" in Revocation List, authentication must fail!!"<<endl;
            data = "fail";
        }
        std::string name = "Send result of revocation list";

        L3Address destAddress = destAddresses[0];
        std::string destAddrStr = destAddressStr[0];
        sendString(name,data,destAddress,destAddrStr);
    }
    delete pk;
    numReceived++;
}

void UdpTrustedAuthority::handleStartOperation(LifecycleOperation *operation)
{
    simtime_t start = std::max(startTime, simTime());
    if ((stopTime < SIMTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)) {
        selfMsg->setKind(START);
        scheduleAt(start, selfMsg);
    }
}

void UdpTrustedAuthority::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void UdpTrustedAuthority::handleCrashOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    socket.destroy();         //TODO  in real operating systems, program crash detected by OS and OS closes sockets of crashed programs.
}

//code from https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/
uint64_t mulmod(uint64_t a, uint64_t b, uint64_t m) {
    int64_t res = 0;

    while (a != 0) {
        if (a & 1) {

            res = (res + b) % m;
        }
        a >>= 1;
        b = (b << 1) % m;
    }
    return res;
}

uint64_t UdpTrustedAuthority::powMod(uint64_t a, uint64_t b, uint64_t n) {
    uint64_t x = 1;

    a %= n;

    while (b > 0) {
        if (b % 2 == 1) {
            x = mulmod(x, a, n); // multiplying with base
        }
        a = mulmod(a, a, n); // squaring the base
        b >>= 1;
    }
    return x % n;
}


// going through all 64 bits and placing randomly 0s and 1s
// setting first and last bit to 1 to get 64 odd number
//MAYBE CHANGE bits TO GET SMALLER NUMBER
uint64_t UdpTrustedAuthority::getRandom64() {
    // the value need to be 63 bits because you can not using 64 bit values do a^2 which is needed
    constexpr int bits = 5;
    std::bitset<bits> a;

    for (int i = 0; i < bits; i++) {
        a[i] = uint64_t(intuniform(0,1));
    }

    a[0] = 1;
    a[bits - 1] = 1;

    return a.to_ullong();
}
std::vector<uint64_t> first_primes = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                                 31, 37, 41, 43, 47, 53, 59, 61, 67,
                                 71, 73, 79, 83, 89, 97, 101, 103,
                                 107, 109, 113, 127, 131, 137, 139,
                                 149, 151, 157, 163, 167, 173, 179,
                                 181, 191, 193, 197, 199, 211, 223,
                                 227, 229, 233, 239, 241, 251, 257,
                                 263, 269, 271, 277, 281, 283, 293,
                                 307, 311, 313, 317, 331, 337, 347, 349 };
uint64_t UdpTrustedAuthority::getLowLevelPrime() {
    while (true) {
        uint64_t candidate = getRandom64();
        bool is_prime = true;
        for (int i = 0; i < first_primes.size(); i++) {
            if (candidate == first_primes[i])
                return candidate;

            if (candidate % first_primes[i] == 0) {
                is_prime = false;
                break;
            }
        }
        if (is_prime)
            return candidate;
    }
}

bool UdpTrustedAuthority::trialComposite(uint64_t a, uint64_t evenC, uint64_t to_test, int max_div_2) {
    if (powMod(a, evenC, to_test) == 1)
        return false;

    for (int i = 0; i < max_div_2; i++) {
        uint64_t temp = static_cast<uint64_t>(1) << i;
        if (powMod(a, temp * evenC, to_test) == to_test - 1)
            return false;
    }

    return true;
}

bool UdpTrustedAuthority::MillerRabinTest(uint64_t to_test) {
    constexpr int accuracy = 20;

    int max_div_2 = 0;
    uint64_t evenC = to_test - 1;
    while (evenC % 2 == 0) {
        evenC >>= 1;
        max_div_2++;
    }

    for (int i = 0; i < accuracy; i++) {
        uint64_t a = uint64_t(intuniform(2,to_test));

        if (trialComposite(a, evenC, to_test, max_div_2)) {
            return false;
        }
    }

    return true;
}

bool UdpTrustedAuthority::PrimeExtraCondition(uint64_t to_test){
    //condition that p-1/2 is also prime
    bool is_prime = true;
    for (int i = 0; i < first_primes.size(); i++) {
        if (to_test == first_primes[i]){
            is_prime = true;
            break;
        }
        if (to_test % first_primes[i] == 0) {
            is_prime = false;
            break;
        }
    }
    is_prime = MillerRabinTest(to_test);
    return is_prime;
}

uint64_t UdpTrustedAuthority::getBigPrime() {
    while (true) {
        uint64_t candidate = uint64_t(intuniform(2,10000));//getLowLevelPrime();
        EV_INFO << "******Candidate=" << candidate << endl;
        bool is_prime = true;
        for (int i = 0; i < first_primes.size(); i++) {
            if (candidate == first_primes[i]){
                break;
            }

            if (candidate % first_primes[i] == 0) {
                is_prime = false;
                break;
            }
        }
        if (is_prime and candidate>1000)
            if ((MillerRabinTest(candidate)) and PrimeExtraCondition((candidate-1)/2)){
                EV_INFO << "******Found Candidate=" << candidate << endl;
                return candidate;
            }
    }
}

//code from https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/

// Function to return gcd of a and b
int64_t UdpTrustedAuthority::gcdExtended(int64_t a, int64_t b,int64_t* x, int64_t* y)
{
    // Base Case
    if (a == 0) {
        *x = 0, *y = 1;
        return b;
    }

    // To store results of recursive call
    int64_t x1, y1;
    int64_t gcd = gcdExtended(b % a, a, &x1, &y1);

    // Update x and y using results of recursive
    // call
    *x = y1 - (b / a) * x1;
    *y = x1;

    return gcd;
}

int64_t UdpTrustedAuthority::modInverse(int64_t A, int64_t M)
{
    int64_t x, y;
    int64_t g = gcdExtended(A, M, &x, &y);
    if (g != 1)
        //Inverse doesn't exist
        return 0;
    else {

        // m is added to handle negative x
        int64_t res = (x % M + M) % M;
        //cout << "Modular multiplicative inverse is " << res;
        return res;
    }
}


// To compute x^y under modulo m
uint64_t modPower(uint64_t x, uint64_t y, uint64_t M)
{
    if (y == 0)
        return 1;

    uint64_t p = modPower(x, y / 2, M) % M;
    p = (p * p) % M;

    return (y % 2 == 0) ? p : (x * p) % M;
}

}// namespace inet

