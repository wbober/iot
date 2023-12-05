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
* The device provides `sensor` resource. The resource supports GET method and should return sensor readings as a plain text. Modify the sample to read sensor and return formated string. Use `coap_packet_append_payload`() method to append data to the payload.
* The example implements coap_get shell command. The syntax is coap_get address resource. Use the command to query sensor resource at a different device.
* Change the request type in coap_get from `COAP_TYPE_NON_CON` to `COAP_TYPE_CON`. Is there any difference between the way messages are exchanged between devices?
* Add more complex resources, for example, `sensor/temp` and `sensor/rh`. Rather than return readings as a plain text use `COAP_CONTENT_FORMAT_APP_OCTET_STREAM`.
* To read the data modify the coap_get command to append more segments of the URI. You also need to modify the print_reply function in order to properly parse content format. You can use `coap_find_options()` to find the `COAP_OPTION_CONTENT_FORMAT` option.
