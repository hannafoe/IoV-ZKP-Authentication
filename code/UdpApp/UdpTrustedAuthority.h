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

#ifndef __INET_UDPTRUSTEDAUTHORITY_H
#define __INET_UDPTRUSTEDAUTHORITY_H

#include <vector>

#include "inet/common/INETDefs.h"

#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

namespace inet {

/**
 * UDP application. See NED for more info.
 */
class INET_API UdpTrustedAuthority : public ApplicationBase, public UdpSocket::ICallback
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

    //numbers needed for registration
    uint64_t a;
    uint64_t b;
    uint64_t t;
    uint64_t l;
    uint64_t s;
    uint64_t n;
    int64_t r_1;
    int64_t r_2;
    uint64_t x;
    uint64_t g_1;
    uint64_t g_2;
    uint64_t h_1;
    uint64_t h_2;
    uint64_t E;
    uint64_t F;
    uint64_t xi_1;
    uint64_t xi_2;
    uint64_t u;
    uint64_t v;
    uint64_t h;
    uint64_t K_i;
    uint64_t T_1;
    uint64_t T_2;
    uint64_t T_3;
    uint64_t MAX_PRIME64 = 2147483647;//18446744073709551557;


    std::map<uint64_t,L3Address> RL; //revocation list
    std::map<uint64_t,L3Address> DB; //Database
    //can also be called with x.first, x.second



  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;
    virtual void refreshDisplay() const override;

    // chooses random destination address
    virtual L3Address chooseDestAddr();
    virtual void sendPacket();
    virtual void sendString(std::string name,std::string data,L3Address destAddress,std::string destAddrStr);
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

    //my extra functions for registration and authentication
    virtual void start_registration();

    //mathematical extra functions

    virtual uint64_t powMod(uint64_t a, uint64_t b, uint64_t n);
    virtual uint64_t getRandom64();
    virtual uint64_t getLowLevelPrime();
    virtual bool trialComposite(uint64_t a, uint64_t evenC, uint64_t to_test, int max_div_2);
    virtual bool MillerRabinTest(uint64_t to_test);
    virtual bool PrimeExtraCondition(uint64_t to_test);
    virtual uint64_t getBigPrime();
    virtual int64_t gcdExtended(int64_t a, int64_t b,int64_t* x, int64_t* y);
    virtual int64_t modInverse(int64_t A, int64_t M);



  public:
    UdpTrustedAuthority() {}
    ~UdpTrustedAuthority();

};
uint64_t modPower(uint64_t x, uint64_t y, uint64_t M);
uint64_t mulmod(uint64_t a, uint64_t b, uint64_t m);

} // namespace inet

#endif // ifndef __INET_UDPTRUSTEDAUTHORITY_H

