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

#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/applications/udpapp/UdpBasicApp.h"
#include "inet/applications/udpapp/UdpTrustedAuthority.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/FragmentationTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"

//I have rewritten UdpBasicApp from INET to represent the class of the VU in the ZAMA protocol

namespace inet {

Define_Module(UdpBasicApp);

UdpBasicApp::~UdpBasicApp()
{
    cancelAndDelete(selfMsg);
}

void UdpBasicApp::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        numSent = 0;
        numReceived = 0;
        WATCH(numSent);
        WATCH(numReceived);
        authCount.setName("auth count");
        authTime.setName("auth time");

        localPort = par("localPort");
        destPort = par("destPort");
        startTime = par("startTime");
        stopTime = par("stopTime");
        packetName = par("packetName");
        dontFragment = par("dontFragment");
        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new cMessage("sendTimer");

    }
}

void UdpBasicApp::finish()
{
    recordScalar("packets sent", numSent);
    recordScalar("packets received", numReceived);
    ApplicationBase::finish();
}

void UdpBasicApp::setSocketOptions()
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

L3Address UdpBasicApp::chooseDestAddr()
{
    int k = 0;//intrand(destAddresses.size());
    if (destAddresses[k].isUnspecified() || destAddresses[k].isLinkLocal()) {
        L3AddressResolver().tryResolve(destAddressStr[k].c_str(), destAddresses[k]);
    }
    return destAddresses[k];
}

void UdpBasicApp::sendPacket()
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
void UdpBasicApp::sendString(std::string name,std::string data,L3Address destAddr,std::string destAddrStr)
{
    if (destAddr.isUnspecified() || destAddr.isLinkLocal()) {
        L3AddressResolver().tryResolve(destAddrStr.c_str(), destAddr);
    }
    auto srcAddress = L3AddressResolver().addressOf(getModuleByPath(getParentModule()->getFullPath().c_str()), 27);
    EV_INFO << "******source address: ****** "  << srcAddress << endl;
    if(data == ""){
        //Send over VID
        std::ostringstream str;
        str << "SourceAddress: "<< srcAddress;
        data = str.str();
    }
    Packet *packet = new Packet(name.c_str());
    if(dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<ApplicationPacket>();
    if(payload->getChunkLength()<B(par("messageLength"))){
        payload->setChunkLength(B(par("messageLength")));
    }
    payload->setSequenceNumber(numSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    payload->setData(data.c_str());
    std::ostringstream srcAdd;
    srcAdd<<srcAddress;
    payload->setSrcAddress(srcAdd.str().c_str());
    payload->setDestAddress(destAddrStr.c_str());
    packet->insertAtBack(payload);
    emit(packetSentSignal, packet);
    EV_INFO << "**********Send source address " << destAddr << destAddrStr << "*********" << endl;
    socket.sendTo(packet, destAddr, destPort);
}
void UdpBasicApp::processStart()
{
    socket.setOutputGate(gate("socketOut"));
    const char *localAddress = par("localAddress");
    socket.bind(*localAddress ? L3AddressResolver().resolve(localAddress) : L3Address(), localPort);
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
    }

    //Send over VID
    //VID = Source address = ipv4 address
    std::string str = "";
    std::string name = "SourceAddress";
    L3Address destAddress = destAddresses[1];
    std::string destAddrStr = destAddressStr[1];//trusted authority
    //BE CAREFUL HARDCODED ADDRESSES, WILL CHANGE WITH CHANGE TO SIMULATION, I.E. MORE RSUs
    EV_INFO << "**********Send source address " << destAddresses[0] << destAddressStr[0] << "*********" << endl;
    EV_INFO << "**********Send source address " << destAddresses[1] << destAddressStr[1] << "*********" << endl;
    sendString(name,str,destAddress,destAddrStr);

    if (!destAddresses.empty()) {
        //Only send messages at request, so do not send any messages here
        simtime_t d = simTime() + par("sendInterval");//uniform(0.000001,0.12);//uniform(0.0001,par("sendInterval"));//par("sendInterval");
        if (stopTime < SIMTIME_ZERO || d < stopTime) {
            selfMsg->setKind(SEND);
            scheduleAt(d, selfMsg);
        }
        else {
            selfMsg->setKind(STOP);
            scheduleAt(stopTime, selfMsg);
        }
    }
    else {
        if (stopTime >= SIMTIME_ZERO) {
            selfMsg->setKind(STOP);
            scheduleAt(stopTime, selfMsg);
        }
    }
}

void UdpBasicApp::processSend()
{
    if(authProcessStarted==true && authenticated==false){//authentication process has started but not yet authenticated

    }else if(authProcessStarted==false){//authentication process has not started yet
        //Send over VID
        //VID = Source address = ipv4 address
        /*std::string str = "";
        std::string name = "SourceAddress";
        L3Address destAddress = destAddresses[1];
        std::string destAddrStr = destAddressStr[1];//trusted authority
        //BE CAREFUL HARDCODED ADDRESSES, WILL CHANGE WITH CHANGE TO SIMULATION, I.E. MORE RSUs
        EV_INFO << "**********Send source address " << destAddresses[0] << destAddressStr[0] << "*********" << endl;
        EV_INFO << "**********Send source address " << destAddresses[1] << destAddressStr[1] << "*********" << endl;
        sendString(name,str,destAddress,destAddrStr);*/
        ///////
        authProcessStarted=true;
        std::string name2 = "Request authentication";
        std::string data = "";
        sendString(name2,data,destAddresses[0],destAddressStr[0]);
        authStart = simTime();
        EV_INFO << "*******Auth Start: " << authStart<< endl;
    }
    else{//authentication process has started and the vehicle is authenticated
        //sendPacket();
    }
    //schedule next time to run this function processSend()
    /*simtime_t d = simTime() + uniform(1.0,1.5);//par("sendInterval");
    if (stopTime < SIMTIME_ZERO || d < stopTime) {
        selfMsg->setKind(SEND);
        scheduleAt(d, selfMsg);
    }
    else {
        selfMsg->setKind(STOP);
        scheduleAt(stopTime, selfMsg);
    }*/
}

void UdpBasicApp::processStop()
{
    socket.close();
}

void UdpBasicApp::handleMessageWhenUp(cMessage *msg)
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

void UdpBasicApp::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    // process incoming packet
    processPacket(packet);
}

void UdpBasicApp::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void UdpBasicApp::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

void UdpBasicApp::refreshDisplay() const
{
    ApplicationBase::refreshDisplay();

    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);
}

void UdpBasicApp::processPacket(Packet *pk)
{
    emit(packetReceivedSignal, pk);
    std::string ReceivedPacket = UdpSocket::getReceivedPacketInfo(pk);
    EV_INFO << "Received packet: " << ReceivedPacket << endl;
    std::string s2("Authorization");
    std::string s1("Nonce");
    std::string s3("Authentication result");
    if(ReceivedPacket.find(s2)!=std::string::npos){
        //Actually a,b,t,l,s,n,g_1,g_2,h_1,h_2 are also needed
        s_1 = 2;
        s_2 = 2;
        b = (uint64_t)pow(2,2);
        t = 2;
        l = 2;
        std::to_string(r_1)+" "+ std::to_string(r_2)+" "+std::to_string(x)+
                                    " "+std::to_string(K_i)+" "+std::to_string(u)+" "+std::to_string(v)+
                                    " "+std::to_string(h)+" "+std::to_string(h_1)+" "+std::to_string(h_2)+
                                    " "+std::to_string(g_1)+" "+std::to_string(g_2)+" "+std::to_string(n);

        const auto& payload  = pk->peekData<ApplicationPacket>();
        auto receivedData = payload->getData();
        EV_INFO << "Received data: " << receivedData<< endl;
        cStringTokenizer tokenizer(receivedData);
        const char *token;
        token = tokenizer.nextToken();
        std::istringstream out1(token);
        out1>>r_1;
        token = tokenizer.nextToken();
        std::istringstream out2(token);
        out2>>r_2;
        token = tokenizer.nextToken();
        std::istringstream out3(token);
        out3>>x;
        token = tokenizer.nextToken();
        std::istringstream out4(token);
        out4>>K_i;
        token = tokenizer.nextToken();
        std::istringstream out5(token);
        out5>>u;
        token = tokenizer.nextToken();
        std::istringstream out6(token);
        out6>>v;
        token = tokenizer.nextToken();
        std::istringstream out7(token);
        out7>>h;
        token = tokenizer.nextToken();
        std::istringstream out8(token);
        out8>>h_1;
        token = tokenizer.nextToken();
        std::istringstream out9(token);
        out9>>h_2;
        token = tokenizer.nextToken();
        std::istringstream out10(token);
        out10>>g_1;
        token = tokenizer.nextToken();
        std::istringstream out11(token);
        out11>>g_2;
        token = tokenizer.nextToken();
        std::istringstream out12(token);
        out12>>n;
        EV_INFO << "Received r_1: " << r_1 << " r_2: "<< r_2 <<endl;
        //Select w, q_1, q_2
        //might be a problem when UINT64_T>>then range of intuniform
        //integer overflow...
        w=uint64_t(intuniform(1,mulmod(modPower(uint64_t(2),t+l,MAX_PRIME64),b,MAX_PRIME64)-1));
        q_1=uint64_t(intuniform(1,mulmod(modPower(2,t+l+s_1,MAX_PRIME64),b,MAX_PRIME64)-1));
        q_2=uint64_t(intuniform(1,mulmod(modPower(2,t+l+s_2,MAX_PRIME64),b,MAX_PRIME64)-1));
        //Compute W_1, W_2
        uint64_t one = modPower(g_1,w,n);
        uint64_t two = modPower(h_1,q_1,n);
        uint64_t three = modPower(g_2,w,n);
        uint64_t four = modPower(h_2,q_2,n);
        W_1 = mulmod(one,two,n);//(modPower(g_1,w,n)*modPower(h_1,q_1,n))%n;
        W_2 = mulmod(three,four,n);

        EV_INFO << "one,two,three,four, W_1, W_2: " << one<<" " <<two<<" "<<three<<" "<<four<<" "<<W_1<<" "<<W_2<< endl;
        EV_INFO << "w, q_1, q_2, W_1, W_2: " << w<<" " <<q_1<<" "<<q_2<<" "<<W_1<<" "<<W_2<< endl;

    }else if(ReceivedPacket.find(s1)!=std::string::npos){
        //Get nonce
        const auto& payload  = pk->peekData<ApplicationPacket>();
        auto receivedData = payload->getData();
        EV_INFO << "Received data: " << receivedData<< endl;
        std::istringstream out1(receivedData);
        out1>>nonce;
        //Upon receipt of nonce, VU randomly chooses K_s as a session key
        //Later change to actual generation of session key
        //For now just take a random int
        K_s = uint64_t(intuniform(1,20));//INT_MAX
        //And we generate the proof P of the user's identity as follows
        //P = {C,D,D_1,D_2}
        //where C, D, D_1, D_2
        //C = H(W_1||W_2||N_d)
        //D = w+Cx
        //D_1 = q_1+Cr_1
        //D_2 = q_2+Cr_2
        //Leave Hashfunction H out for now...
        C=W_1||W_2||nonce;
        D=w+mulmod(C,x,MAX_PRIME64);
        D_1 = q_1+mulmod(C,r_1,MAX_PRIME64);
        D_2 = q_2+mulmod(C,r_2,MAX_PRIME64);
        //Then generate numbers alpha, beta and calculate
        uint64_t alpha = uint64_t(intuniform(1,2));//INT_MAX
        uint64_t beta = uint64_t(intuniform(1,2));//INT_MAX
        //the following parameter's with secret key K_i
        //T_1 = u**alpha
        //T_2 = v**beta
        //T_3 = K_i*h**(alpha+beta)
        //changed K_i belonging
        T_1 = modPower(u,alpha,MAX_PRIME64);
        T_2 = modPower(v,beta,MAX_PRIME64);
        T_3 = mulmod(K_i,modPower(h,alpha+beta,MAX_PRIME64),MAX_PRIME64);
        //Encrypt {K_s,C,D,D_1,D_2,T_1,T_2,T_3} with AS's public key PK_H
        //And send this to AS
        //For now send without encrypting
        std::string packetName = "Authentication variables";
        std::string str = std::to_string(K_s)+" "+ std::to_string(C)+" "+std::to_string(D)+
                            " "+std::to_string(D_1)+" "+std::to_string(D_2)+" "+std::to_string(T_1)+
                            " "+std::to_string(T_2)+" "+std::to_string(T_3);
        auto destAddressStr = payload->getSrcAddress();//L3AddressResolver().addressOf(getModuleByPath(pk->getSenderModule()->getFullPath().c_str()), 27);
        L3Address destAddress;
        L3AddressResolver().tryResolve(destAddressStr, destAddress);
        EV_INFO << "Destination address" << destAddress <<endl;
        EV_INFO<< "**********Sending: K_s, C, D, D_1, D_2, T_1, T_2, T_3"<<str<<endl;
        sendString(packetName,str,destAddress,destAddressStr);

    }else if(ReceivedPacket.find(s3)!=std::string::npos){
        //Finally send the packet that we wanted to send in the first place
        //if message == "success"
        const auto& payload  = pk->peekData<ApplicationPacket>();
        auto receivedData = payload->getData();
        EV_INFO << "Received data: " << receivedData<< endl;
        char res[] = "success";
        if(strcmp(receivedData,res)==0){
            authenticated=true;
            sendPacket();
            authEnd = simTime();
            authCounter+=1;
            EV_INFO << "Auth time: " << authEnd-authStart<< endl;
            EV_INFO << "Start: " << authStart<< endl;
            EV_INFO << "End: " << authEnd<< endl;
            authTime.record(authEnd-authStart);
            authCount.record(authCounter);
        }else{
            //Not authenticated
        }

    }
    delete pk;
    numReceived++;
}

void UdpBasicApp::handleStartOperation(LifecycleOperation *operation)
{
    simtime_t start = std::max(startTime, simTime());
    if ((stopTime < SIMTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)) {
        selfMsg->setKind(START);
        scheduleAt(start, selfMsg);
    }
}

void UdpBasicApp::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void UdpBasicApp::handleCrashOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    socket.destroy();         //TODO  in real operating systems, program crash detected by OS and OS closes sockets of crashed programs.
}

} // namespace inet

