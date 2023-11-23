# Dissertation code

This folder contains the following folders and files that are parts of packages used for the simulation of the VANET in my dissertation:
NOTE: The code cannot be run as is because they are dependent on the simulation packages OMNET++, INET, SUMO and VEINS.

## UdpApp folder
This folder includes code that belongs into the Application layer folder of the INET package. Code base from INET was used to implement the ZAMA protocol in the following files:

- `UdpApp.ned`: The base for all ned files in UdpApp. The code is from INET.
- `UdpBasicApp.cc/.h/.ned`: The code needed to run the VU as part of a simulation of the ZAMA protocol. The UdpBasicApp code from INET was adapted to include the authentication protocol from ZAMA.
- `UdpBasicBurst.cc/.h/.ned`: The code needed to run the RSU as part of a simulation of the ZAMA protocol. The UdpBasicBurst code from INET was adapted to include the authentication protocol from ZAMA.
- `UdpTrustedAuthority.cc/.h/.ned`: The code needed to run the Trusted Authority as part of a simulation of the ZAMA protocol. The UdpTrustedAuthority code from INET was adapted to include the authentication protocol from ZAMA.

## VANET folder
This folder is based on code from the github repo https://github.com/chaotictoejam/VANETProject. Some parts where adapted for the purpose of the simulation.
### _maps
Includes the map of the simulation and the routes of vehicles.
- `config.xml`: Configuration file of simulation.
- `[].launchd.xml`: Includes the file locations of files that are important for launching the simulation.
- `[].net.xml`: Includes the specifics of the road network.
- `[].rou.xml`: Includes the specifics on when each vehicle departs, where it departs from and where it is headed.
- `[].sumo.cfg`: Includes setup configurations for SUMO.
### vanet
- `_nodes`: This folder includes the files specifying the dependency of each instance such as the VU with the appropriate INET files.
- `aodv`: This folder includes the two files `AODVSim.ned` and `omnetpp.ini` that specify the run of the simulation for OMNET++.