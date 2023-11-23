//
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
// Copyright (C) 2007 Universidad de Málaga
// Copyright (C) 2011 Zoltan Bojthe
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//


#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/applications/udpapp/UdpBasicBurst.h"
#include "inet/applications/udpapp/UdpTrustedAuthority.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/FragmentationTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"
#include "inet/common/packet/printer/PacketPrinter.h"
#include "inet/common/packet/printer/ProtocolPrinterRegistry.h"

//I have rewritten UdpBasicBurst from INET to represent the class of the RSU in the ZAMA protocol

namespace inet {

EXECUTE_ON_STARTUP(
        cEnum * e = cEnum::find("inet::ChooseDestAddrMode");
        if (!e)
            enums.getInstance()->add(e = new cEnum("inet::ChooseDestAddrMode"));
        e->insert(UdpBasicBurst::ONCE, "once");
        e->insert(UdpBasicBurst::PER_BURST, "perBurst");
        e->insert(UdpBasicBurst::PER_SEND, "perSend");
        );

Define_Module(UdpBasicBurst);

int UdpBasicBurst::counter;

simsignal_t UdpBasicBurst::outOfOrderPkSignal = registerSignal("outOfOrderPk");

UdpBasicBurst::~UdpBasicBurst()
{
    cancelAndDelete(timerNext);
}

void UdpBasicBurst::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        counter = 0;
        numSent = 0;
        numReceived = 0;
        numDeleted = 0;
        numDuplicated = 0;

        delayLimit = par("delayLimit");
        startTime = par("startTime");
        stopTime = par("stopTime");
        if (stopTime >= SIMTIME_ZERO && stopTime <= startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");

        messageLengthPar = &par("messageLength");
        burstDurationPar = &par("burstDuration");
        sleepDurationPar = &par("sleepDuration");
        sendIntervalPar = &par("sendInterval");
        nextSleep = startTime;
        nextBurst = startTime;
        nextPkt = startTime;
        dontFragment = par("dontFragment");

        destAddrRNG = par("destAddrRNG");
        const char *addrModeStr = par("chooseDestAddrMode");
        int addrMode = cEnum::get("inet::ChooseDestAddrMode")->lookup(addrModeStr);
        if (addrMode == -1)
            throw cRuntimeError("Invalid chooseDestAddrMode: '%s'", addrModeStr);
        chooseDestAddrMode = static_cast<ChooseDestAddrMode>(addrMode);

        WATCH(numSent);
        WATCH(numReceived);
        WATCH(numDeleted);
        WATCH(numDuplicated);

        localPort = par("localPort");
        destPort = par("destPort");

        timerNext = new cMessage("UDPBasicBurstTimer");
    }
}

L3Address UdpBasicBurst::chooseDestAddr()
{
    if (destAddresses.size() == 1){
        return destAddresses[0];
    }
    int k = getRNG(destAddrRNG)->intRand(destAddresses.size());
    while(k==0){
        k = getRNG(destAddrRNG)->intRand(destAddresses.size());
    }
    return destAddresses[k];
}

Packet *UdpBasicBurst::createPacket()
{
    char msgName[32];
    sprintf(msgName, "RSUBurstData-%d", counter++);//"UDPBasicAppData-%d"
    long msgByteLength = *messageLengthPar;
    Packet *pk = new Packet(msgName);
    const auto& payload = makeShared<ApplicationPacket>();
    payload->setChunkLength(B(msgByteLength));
    payload->setSequenceNumber(numSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    pk->insertAtBack(payload);
    pk->addPar("sourceId") = getId();
    pk->addPar("msgId") = numSent;

    return pk;
}

void UdpBasicBurst::sendString(std::string name,std::string data,L3Address destAddr,std::string destAddrStr)
{
    if (destAddr.isUnspecified() || destAddr.isLinkLocal()) {
        L3AddressResolver().tryResolve(destAddrStr.c_str(), destAddr);
    }

    Packet *packet = new Packet(name.c_str());
    if(dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<ApplicationPacket>();
    long msgByteLength = *messageLengthPar;
    if(payload->getChunkLength()<B(msgByteLength)){
        payload->setChunkLength(B(msgByteLength));
    }
    payload->setSequenceNumber(numSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    payload->setData(data.c_str());
    std::ostringstream srcAdd;
    auto srcAddress = L3AddressResolver().addressOf(getModuleByPath(getParentModule()->getFullPath().c_str()), 27);
    srcAdd<<srcAddress;
    payload->setSrcAddress(srcAdd.str().c_str());
    payload->setDestAddress(destAddrStr.c_str());
    packet->insertAtBack(payload);
    packet->addPar("sourceId") = getId();
    packet->addPar("msgId") = numSent;
    emit(packetSentSignal, packet);
    EV_INFO << "**********Send source address " << destAddrStr << "*********" << endl;
    socket.sendTo(packet, destAddr, destPort);
}
void UdpBasicBurst::processStart()
{
    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(localPort);

    int timeToLive = par("timeToLive");
    if (timeToLive != -1)
        socket.setTimeToLive(timeToLive);

    int dscp = par("dscp");
    if (dscp != -1)
        socket.setDscp(dscp);

    int tos = par("tos");
    if (tos != -1)
        socket.setTos(tos);

    const char *destAddrs = par("destAddresses");
    cStringTokenizer tokenizer(destAddrs);
    const char *token;
    bool excludeLocalDestAddresses = par("excludeLocalDestAddresses");

    IInterfaceTable *ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);

    while ((token = tokenizer.nextToken()) != nullptr) {
        if (strstr(token, "Broadcast") != nullptr)
            destAddresses.push_back(Ipv4Address::ALLONES_ADDRESS);
        else {
            L3Address addr = L3AddressResolver().resolve(token);
            if (excludeLocalDestAddresses && ift && ift->isLocalAddress(addr))
                continue;
            destAddresses.push_back(addr);
        }
    }
    //get E, F from Trusted Authority
    /*
    destAddr = destAddresses[0];
    Packet *payload = createDemandPacket();
    if(dontFragment)
        payload->addTag<FragmentationReq>()->setDontFragment(true);
    payload->setTimestamp();
    emit(packetSentSignal, payload);
    socket.sendTo(payload, destAddr, destPort);*/


    nextSleep = simTime();
    nextBurst = simTime();
    nextPkt = simTime();
    activeBurst = false;

    isSource = false;//!destAddresses.empty();

    if (isSource) {
        if (chooseDestAddrMode == ONCE)
            destAddr = chooseDestAddr();

        activeBurst = true;
    }
    timerNext->setKind(SEND);
    processSend();
}

void UdpBasicBurst::processSend()
{
    if (stopTime < SIMTIME_ZERO || simTime() < stopTime) {
        // send and reschedule next sending
        if (isSource) // if the node is a sink, don't generate messages
            generateBurst();
    }
}

void UdpBasicBurst::processStop()
{
    socket.close();
    socket.setCallback(nullptr);
}

void UdpBasicBurst::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        switch (msg->getKind()) {
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
                throw cRuntimeError("Invalid kind %d in self message", (int)msg->getKind());
        }
    }
    else
        socket.processMessage(msg);
}

void UdpBasicBurst::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    // process incoming packet
    processPacket(packet);
}

void UdpBasicBurst::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void UdpBasicBurst::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

void UdpBasicBurst::refreshDisplay() const
{
    ApplicationBase::refreshDisplay();

    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);
}

void UdpBasicBurst::processPacket(Packet *pk)
{
    if (pk->getKind() == UDP_I_ERROR) {
        EV_WARN << "UDP error received\n";
        delete pk;
        return;
    }

    if (pk->hasPar("sourceId") && pk->hasPar("msgId")) {
        // duplicate control
        int moduleId = pk->par("sourceId");
        int msgId = pk->par("msgId");
        auto it = sourceSequence.find(moduleId);
        if (it != sourceSequence.end()) {
            if (it->second >= msgId) {
                EV_DEBUG << "Out of order packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;
                emit(outOfOrderPkSignal, pk);
                delete pk;
                numDuplicated++;
                return;
            }
            else
                it->second = msgId;
        }
        else
            sourceSequence[moduleId] = msgId;
    }

    if (delayLimit > 0) {
        if (simTime() - pk->getTimestamp() > delayLimit) {
            EV_DEBUG << "Old packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;
            PacketDropDetails details;
            details.setReason(CONGESTION);
            emit(packetDroppedSignal, pk, &details);
            delete pk;
            numDeleted++;
            return;
        }
    }

    std::string packetInfo = UdpSocket::getReceivedPacketInfo(pk);
    EV_INFO << "Received packet: " << packetInfo << endl;
    std::string s1("Commitments");
    std::string s2("Request");
    std::string s3("Authentication variables");
    std::string s4("revocation list");
    if(packetInfo.find(s1)!=std::string::npos){
        EV_INFO << "Received packet includes commitments E and F" << endl;
        //store E and F in RSU
        const auto& payload  = pk->peekData<ApplicationPacket>();
        auto receivedData = payload->getData();
        EV_INFO << "Received data: " << receivedData<< endl;
        cStringTokenizer tokenizer(receivedData);
        const char *token;
        token = tokenizer.nextToken();
        token = tokenizer.nextToken();
        std::istringstream out1(token);
        out1>>E;
        token = tokenizer.nextToken();
        token = tokenizer.nextToken();
        std::istringstream out3(token);
        out3>>F;
        token = tokenizer.nextToken();
        std::istringstream out4(token);
        out4>>h_1;
        token = tokenizer.nextToken();
        std::istringstream out5(token);
        out5>>h_2;
        token = tokenizer.nextToken();
        std::istringstream out6(token);
        out6>>g_1;
        token = tokenizer.nextToken();
        std::istringstream out7(token);
        out7>>g_2;
        token = tokenizer.nextToken();
        std::istringstream out8(token);
        out8>>n;
        EV_INFO << "Commitments E and F " << E << " "<< F <<endl;
    }
    else if(packetInfo.find(s2)!=std::string::npos){
        EV_INFO << "*****Received authentication request*****" << endl;
        //Send nonce to vehicle
        std::string name = "Sending Nonce";
        uint64_t nonce = uint64_t(intuniform(0,MAX_PRIME64));
        std::string data = std::to_string(nonce);
        const auto& payload  = pk->peekData<ApplicationPacket>();
        auto destAddressStr = payload->getSrcAddress();//L3AddressResolver().addressOf(getModuleByPath(pk->getSenderModule()->getFullPath().c_str()), 27);
        L3Address destAddress;
        L3AddressResolver().tryResolve(destAddressStr, destAddress);
        EV_INFO << "Destination address" << destAddress <<endl;
        sendString(name,data,destAddress,destAddressStr);

    }else if(packetInfo.find(s3)!=std::string::npos){
        EV_INFO<<"******Received authentication variables*******"<<endl;
        const auto& payload  = pk->peekData<ApplicationPacket>();
        auto receivedData = payload->getData();
        EV_INFO << "Received data: " << receivedData<< endl;
        //Decrypt {K_s,C,D,D_1,D_2,T_1,T_2,T_3} with AS's private key PK_H
        //Skipping decryption step
        cStringTokenizer tokenizer(receivedData);
        const char *token;
        token = tokenizer.nextToken();
        std::istringstream out1(token);
        out1>>K_s;
        token = tokenizer.nextToken();
        std::istringstream out2(token);
        out2>>C;
        token = tokenizer.nextToken();
        std::istringstream out3(token);
        out3>>D;
        token = tokenizer.nextToken();
        std::istringstream out4(token);
        out4>>D_1;
        token = tokenizer.nextToken();
        std::istringstream out5(token);
        out5>>D_2;
        token = tokenizer.nextToken();
        std::istringstream out6(token);
        out6>>T_1;
        token = tokenizer.nextToken();
        std::istringstream out7(token);
        out7>>T_2;
        token = tokenizer.nextToken();
        std::istringstream out8(token);
        out8>>T_3;
        std::list<uint64_t> l{K_s,C,D,D_1,D_2,T_1,T_2,T_3};
        TempMem.push_back(l);
        auto destAddrStr = payload->getSrcAddress();
        TempAddr.push_back(destAddrStr);

        //D holds the secret x which cannot be accessed by illegal VUs
        //AS sends {T_1,T_2,T_3} to TA through secret security channel
        //to check whether VU is in RL
        L3Address destAddress = destAddresses[0];
        std::ostringstream str;
        str <<  destAddress;
        std::string destAddressStr =str.str();
        std::string name = "Check if VU in RL";
        std::string data = std::to_string(T_1)+" "+std::to_string(T_2)+" "+std::to_string(T_3);
        EV_INFO<<"Sending to: "<<destAddressStr<<endl;
        sendString(name,data,destAddress,destAddressStr);
    }else if(packetInfo.find(s4)!=std::string::npos){
        EV_INFO <<"****Result from revocation list"<<endl;
        //Technically would need to check the sender ip
        //to make sure this message was sent from the Trusted authority
        const auto& payload  = pk->peekData<ApplicationPacket>();
        auto receivedData = payload->getData();
        EV_INFO << "Received data: " << receivedData<< endl;
        char res[] = "success";
        L3Address destAddress;
        std::string destAddrStr = TempAddr.front();
        TempAddr.pop_front();
        L3AddressResolver().tryResolve(destAddrStr.c_str(), destAddress);
        if(strcmp(receivedData,res)==0){
            EV_INFO << "Not in Revocation list, can continue authentication"<< endl;
            //Continue verification of VU with following equation
            //C = H(g_1**D*h_1**D_1*E**-C mod n||g_2**D*h_2**D_2*F**-C mod n||Nonce)
            //Leave out hash function for now

            std::list<uint64_t> myVars = TempMem.front();
            TempMem.pop_front();
            std::list<uint64_t>::iterator it;
            uint64_t VarNames[8]= {K_s,C,D,D_1,D_2,T_1,T_2,T_3};
            int count =0;
            for (it = myVars.begin(); it != myVars.end(); ++it){
                VarNames[count] = *it;
                count++;
            }
            std::string str = std::to_string(K_s)+" "+ std::to_string(C)+" "+std::to_string(D)+
                                " "+std::to_string(D_1)+" "+std::to_string(D_2)+" "+std::to_string(T_1)+
                                " "+std::to_string(T_2)+" "+std::to_string(T_3);
            EV_INFO<< "**********From memory: K_s, C, D, D_1, D_2, T_1, T_2, T_3"<<str<<endl;
            uint64_t result = mulmod(mulmod(modPower(g_1,D,n),modPower(h_1,D_1,n),n),modPower(E,-C,n),n)||
                    mulmod(mulmod(modPower(g_2,D,n),modPower(h_2,D_2,n),n),modPower(F,-C,n),n)||nonce;
            if (result==C){
                EV_INFO << "Authentication successful: "<<result<<" = "<<C<< endl;
                //AS encrypts message using session key K_s and sends it to VU
                std::string name = "Authentication result";
                std::string data = "success";
                EV_INFO<<"Sending to: "<<destAddrStr<<endl;
                sendString(name,data,destAddress,destAddrStr);
                //AS maintains an activation list AL which contains recent VUs who have been successfully authenticated.

                std::list<uint64_t> ll{K_s,T_1,T_2,T_3};
                AL.push_back(ll);
                //VUs are recorded in the form of {K_s,T_1,T_2,T_3}, AS cannot observe the real identity
                //If VU can decrypt the message sent by AS with K_s, it turns out AS is legal
                //and the authentication is over
            }else{
                EV_INFO << "Authentication unsuccessful: "<<result<<" != "<<C<< endl;
                std::string name = "Authentication result";
                std::string data = "failed";
                EV_INFO<<"Sending to: "<<destAddrStr<<endl;
                sendString(name,data,destAddress,destAddrStr);
            }

        }else{
            EV_INFO << "In Revocation list, cannot continue authentication"<< endl;
            //Send failed authentication to vehicle
            std::string name = "Authentication result";
            std::string data = "failed";
            EV_INFO<<"Sending to: "<<destAddrStr<<endl;
            sendString(name,data,destAddress,destAddrStr);
        }

    }
    emit(packetReceivedSignal, pk);
    numReceived++;
    delete pk;
}


void UdpBasicBurst::generateBurst()
{
    simtime_t now = simTime();
    EV_INFO << "Generating Burst: destaddress size: " << destAddresses.size()<< endl;

    if (nextPkt < now)
        nextPkt = now;

    double sendInterval = *sendIntervalPar;
    if (sendInterval <= 0.0)
        throw cRuntimeError("The sendInterval parameter must be bigger than 0");
    nextPkt += sendInterval;

    if (activeBurst && nextBurst <= now) {    // new burst
        double burstDuration = *burstDurationPar;
        if (burstDuration < 0.0)
            throw cRuntimeError("The burstDuration parameter mustn't be smaller than 0");
        double sleepDuration = *sleepDurationPar;

        if (burstDuration == 0.0)
            activeBurst = false;
        else {
            if (sleepDuration < 0.0)
                throw cRuntimeError("The sleepDuration parameter mustn't be smaller than 0");
            nextSleep = now + burstDuration;
            nextBurst = nextSleep + sleepDuration;
        }

        if (chooseDestAddrMode == PER_BURST)
            destAddr = chooseDestAddr();
    }

    if (chooseDestAddrMode == PER_SEND)
        destAddr = chooseDestAddr();

    //if(destAddresses.size() != 1){
    Packet *payload = createPacket();
    if(dontFragment)
        payload->addTag<FragmentationReq>()->setDontFragment(true);
    payload->setTimestamp();
    emit(packetSentSignal, payload);
    socket.sendTo(payload, destAddr, destPort);
    numSent++;
    //}

    // Next timer
    if (activeBurst && nextPkt >= nextSleep)
        nextPkt = nextBurst;

    if (stopTime >= SIMTIME_ZERO && nextPkt >= stopTime) {
        timerNext->setKind(STOP);
        nextPkt = stopTime;
    }
    scheduleAt(nextPkt, timerNext);
}

void UdpBasicBurst::finish()
{
    recordScalar("Total sent", numSent);
    recordScalar("Total received", numReceived);
    recordScalar("Total deleted", numDeleted);
    ApplicationBase::finish();
}

void UdpBasicBurst::handleStartOperation(LifecycleOperation *operation)
{
    simtime_t start = std::max(startTime, simTime());

    if ((stopTime < SIMTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)) {
        timerNext->setKind(START);
        scheduleAt(start, timerNext);
    }
}

void UdpBasicBurst::handleStopOperation(LifecycleOperation *operation)
{
    if (timerNext)
        cancelEvent(timerNext);
    activeBurst = false;
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void UdpBasicBurst::handleCrashOperation(LifecycleOperation *operation)
{
    if (timerNext)
        cancelEvent(timerNext);
    activeBurst = false;
    if (operation->getRootModule() != getContainingNode(this))     // closes socket when the application crashed only
        socket.destroy();         //TODO  in real operating systems, program crash detected by OS and OS closes sockets of crashed programs.
}

} // namespace inet

