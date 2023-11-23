//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package vanetsim.simulations.vanet._nodes;

import inet.node.inet.WirelessHost;
import inet.applications.contract.IApp;

module TrustedAuthority extends WirelessHost
{
    parameters:
        @display("i=abstract/server");
        ipv4.configurator.networkConfiguratorModule = "";
    	string router;
        //wlan[*].mgmt.typename = default("Ieee80211MgmtSta");
        //wlan[*].agent.typename = default("Ieee80211AgentSta");
        wlan[*].mgmt.typename = default("Ieee80211MgmtAdhoc");
        wlan[*].agent.typename = default("");
        forwarding = default(true);
    submodules:
        routing: <router> like IApp {
            @display("p=558,307");
        }
    connections allowunconnected:
        routing.socketOut --> at.in++;
        routing.socketIn <-- at.out++;
}