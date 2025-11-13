.. _packet-socket-sample:

Introduction to IoT - Thread
############################

Overview
********

This sample is a simple socket application showing usage of UDP sockets over 802.15.4.

Building and Running
********************
When the application is run, it opens a packet socket and prints the length of the packet it receives. After that it sends a dummy packet every 5 seconds.

Preparation
***********

* Install Wireshark from wireshark.org
* Install the 802.15.4 sniffer plugin using `the following instructions <https://infocenter.nordicsemi.com/topic/ug_sniffer_802154/UG/sniffer_802154/installing_sniffer_802154.html>`_
* `Configure the sniffer for Thread <https://infocenter.nordicsemi.com/topic/ug_sniffer_802154/UG/sniffer_802154/configuring_sniffer_802154_thread.html>`_
*

Tasks
*****
* The sample has a shell. You can type `help` to see what is available. `OpenThread CLI reference might also be useful <https://github.com/openthread/openthread/blob/main/src/cli/README.md>`_. Note that you need to prefix openthread commands with `ot`.
* Is your device connected to the network? You can check that using `ot state`.
* Check the IP addresses that you device has. You can use `net iface` shell command to do that. What addresses does your device have?
* Check the neighbor table. You can use `ot neighbor table` shell command to do that. What devices are in the neighbor table?
* Check the router table. You can use `ot router table` shell command to do that. What devices are in the router table? Can you identify any devices in the router table that are not in the neighbor table?
* You can ping the whole network using one of the multicast addresses. For example, try `ff02::1` or `ff03::1`. Use `net ping` command to do that. Can you explain the difference between the addresses?
* The program opens a UDP socket at port 1234. Depending on the hardware you have, you can send and receive commands to control the LED strip and and read the BME280 sensor. Test the functionality by sending commands to the leader of the network.
* Modify the program by adding an echo command that will echo back the received packet. You can use `sendto` function to send a packet back to the sender.
* Use `ot udp open` and `ot udp send` commands to send a packet to another device. Use an address that you have discovered in previous steps. What did the peer device replied back? Can you identify the packet in Wireshark?
