.. _packet-socket-sample:

802.15.4 Packet socket sample
#############################

Overview
********

This sample is a simple packet socket application showing usage of packet sockets over 802.15.4. The sample prints every packet received, and sends a dummy packet every 5 seconds. The Zephyr network subsystem does not touch any of the headers (L2, L3, etc.).

Building and Running
********************
When the application is run, it opens a packet socket and prints the length of the packet it receives. After that it sends a dummy packet every 5 seconds.

Preparation
***********

* Install Wireshark from wireshark.org
* Install the 802.15.4 sniffer plugin using `the following instructions <https://infocenter.nordicsemi.com/topic/ug_sniffer_802154/UG/sniffer_802154/installing_sniffer_802154.html>`

Tasks
*****

1. Identify packets send by your device in Wireshark. The devices are using channel #15. Use Wireshark filter function to filter out packets from other devices. Inspect the packet contents. What type of addressing is used?
2. Modify the program, so that it uses short address. You can set an address of your device using the following code:

.. code-block:: c

    uint16_t short_addr = 0x1234; // change this to an address of your liking
    ret = net_mgmt(NET_REQUEST_IEEE802154_SET_SHORT_ADDR, iface, &short_addr, sizeof(short_addr));
    if (ret) {
        NET_ERR("*** Failed to set short address\n");
    }

4. Modify the program, so that it sends the data only on a button press. The button press should be detected using an interrupt. Remember that sending data directly from interrupt is not a good idea.
5. Modify the sample, so that the packet contains data from BME280 environmental sensor. If you don't have you don't have a the sensor then send button press counter value.
6. Modify the program, so that it sends data to a unicast rather than broadcast address. You can use the address of one of your classmates.
7. Modify the program, so that an acknowledgement is requested on a unicast packet. You can use the following code:

.. code-block:: c

	ret = net_mgmt(NET_REQUEST_IEEE802154_SET_ACK, iface, NULL, 0);
	if (ret) {
		NET_ERR("*** Failed to set ack request addr\n");
	}
