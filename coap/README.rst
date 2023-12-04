.. _packet-socket-sample:

Introduction to IoT - CoAP
##########################

Overview
********

This sample demonstrates usage of CoAP protocol over 802.15.4.

Building and Running
********************
When the application is run, it opens a UDP socket at CoAP port 5683. The application
then waits for a CoAP message to be received. When a message is received, the application replies with sensor data.

Preparation
***********

* Install Wireshark from wireshark.org
* Install the 802.15.4 sniffer plugin using `the following instructions <https://infocenter.nordicsemi.com/topic/ug_sniffer_802154/UG/sniffer_802154/installing_sniffer_802154.html>`_
* `Configure the sniffer for Thread <https://infocenter.nordicsemi.com/topic/ug_sniffer_802154/UG/sniffer_802154/configuring_sniffer_802154_thread.html>`_
*

Tasks
*****
* https://docs.zephyrproject.org/latest/connectivity/networking/api/coap_client.html#coap-client-interface