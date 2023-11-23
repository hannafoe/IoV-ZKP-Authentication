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

#ifndef __INET_UDPBASICAPP_H
#define __INET_UDPBASICAPP_H

#include <vector>

#include "inet/common/INETDefs.h"

#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

namespace inet {

/**
 * UDP application. See NED for more info.
 */
class INET_API UdpBasicApp : public ApplicationBase, public UdpSocket::ICallback
{
  protected:
    enum SelfMsgKinds { START = 1, SEND, STOP };

    // parameters
    std::vector<L3Address> destAddresses;
    std::vector<std::string> destAddressStr;
    int localPort = -1, destPort = -1;
    simtime_t startTime;
    simtime_t stopTime;
    bool dontFragment = false;
    const char *packetName = nullptr;


    // state
    UdpSocket socket;
    cMessage *selfMsg = nullptr;

    // statistics
    int numSent = 0;
    int numReceived = 0;
    int authCounter = 0;
    cOutVector authCount;
    cOutVector authTime;
    simtime_t authStart;
    simtime_t authEnd;
    //const_simtime_t authStart;
    //const_simtime_t authEnd;


    //parameters for authentication protocol
    uint64_t a;
    uint64_t b;
    uint64_t t;
    uint64_t l;
    uint64_t s_1;
    uint64_t s_2;
    uint64_t n;
    int64_t r_1;
    int64_t r_2;
    uint64_t x;
    uint64_t g_1;
    uint64_t g_2;
    uint64_t h_1;
    uint64_t h_2;
    uint64_t u;
    uint64_t v;
    uint64_t h;
    uint64_t K_i;
    uint64_t w;
    uint64_t q_1;
    uint64_t q_2;
    uint64_t W_1;
    uint64_t W_2;
    bool authenticated=false;
    bool authProcessStarted=false;
    uint64_t nonce;
    uint64_t K_s;
    uint64_t C;
    uint64_t D;
    uint64_t D_1;
    uint64_t D_2;
    uint64_t T_1;
    uint64_t T_2;
    uint64_t T_3;
    uint64_t MAX_PRIME64 = 2147483647;//18446744073709551557;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;
    virtual void refreshDisplay() const override;

    // chooses random destination address
    virtual L3Address chooseDestAddr();
    virtual void sendPacket();
    virtual void sendString(std::string name,std::string data,L3Address destAddr,std::string destAddrStr);
    virtual void processPacket(Packet *msg);
    virtual void setSocketOptions();

    virtual void processStart();
    virtual void processSend();
    virtual void processStop();

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
    virtual void socketClosed(UdpSocket *socket) override;

  public:
    UdpBasicApp() {}
    ~UdpBasicApp();
};

} // namespace inet

#endif // ifndef __INET_UDPBASICAPP_H

