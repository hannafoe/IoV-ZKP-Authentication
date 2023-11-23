
package vanetsim.simulations.vanet.aodv;


import org.car2x.veins.base.connectionManager.ConnectionManager;
import org.car2x.veins.base.modules.BaseWorldUtility;
import org.car2x.veins.modules.mobility.traci.TraCIScenarioManager*;
import org.car2x.veins.modules.obstacle.ObstacleControl;
import org.car2x.veins.modules.world.annotations.AnnotationManager;

import inet.physicallayer.contract.packetlevel.IRadioMedium;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.networklayer.ipv4.RoutingTableRecorder;
import vanetsim.simulations.vanet._nodes.Car;
import vanetsim.simulations.vanet._nodes.RSU;
import vanetsim.simulations.vanet._nodes.TrustedAuthority;
import inet.visualizer.integrated.IntegratedCanvasVisualizer;
import inet.visualizer.contract.IIntegratedVisualizer;
import inet.visualizer.integrated.IntegratedMultiVisualizer;

import veins_inet.VeinsInetManager;
//All of this code and the maps are adapted from https://github.com/chaotictoejam/VANETProject
//The code was only adjusted so that it fits my project

network AODVSim
{
    parameters:
        double playgroundSizeX @unit(m); // x size of the area the nodes are in (in meters)
        double playgroundSizeY @unit(m); // y size of the area the nodes are in (in meters)
        double playgroundSizeZ @unit(m); // z size of the area the nodes are in (in meters)
        @display("bgb=$playgroundSizeX,$playgroundSizeY");
        @figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);
        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,18; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=rsu[0].app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);
    	string radioMediumType;
    	int numberOfRSU;
    submodules:
        manager: VeinsInetManager{
                @display("p=150,0;i=abstract/multicast");
        }
        //visualizer: <default(firstAvailableOrEmpty("IntegratedCanvasVisualizer"))> like IIntegratedVisualizer if typename != "" {
        //    @display("p=580,125");
        //}
        //visualizer: IntegratedMultiVisualizer {
        //    @display("p=100,200");
        //}
        radioMedium: <radioMediumType> like IRadioMedium {
            parameters:
                @display("p=50,50");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=580,200");
        }
        routingTableRecorder: RoutingTableRecorder {
            parameters:
                @display("p=100,300;is=s");
        }
        
        rsu[numberOfRSU]: RSU {
        }
        
        vehicle[0]: Car {
        }
        trustedAuthority[1]:TrustedAuthority{
        }
    connections allowunconnected:
}