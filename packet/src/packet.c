/*
 * Copyright (c) 2019 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_pkt_sock_sample, LOG_LEVEL_DBG);

#include <zephyr/kernel.h>
#include <errno.h>
#include <stdio.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/sensor.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/ieee802154.h>
#include <zephyr/net/ieee802154_mgmt.h>
#include <zephyr/net/net_mgmt.h>

#define STACK_SIZE 4096
#if defined(CONFIG_NET_TC_THREAD_COOPERATIVE)
#define THREAD_PRIORITY K_PRIO_COOP(CONFIG_NUM_COOP_PRIORITIES - 1)
#else
#define THREAD_PRIORITY K_PRIO_PREEMPT(8)
#endif
#define RECV_BUFFER_SIZE 128
#define WAIT_TIME CONFIG_NET_SAMPLE_SEND_WAIT_TIME

#define FLOOD (CONFIG_NET_SAMPLE_SEND_WAIT_TIME ? 0 : 1)

static struct k_sem quit_lock;

struct packet_data {
	int send_sock;
	int recv_sock;
	char recv_buffer[RECV_BUFFER_SIZE];
};

static struct packet_data packet;
static bool finish;
static K_SEM_DEFINE(iface_up, 0, 1);
static char buffer[RECV_BUFFER_SIZE] = "This is sample data";
static const struct device *bme280 = NULL;

static void recv_packet(void);
static void send_packet(void);

K_THREAD_DEFINE(receiver_thread_id, STACK_SIZE,
		recv_packet, NULL, NULL, NULL,
		THREAD_PRIORITY, 0, -1);
K_THREAD_DEFINE(sender_thread_id, STACK_SIZE,
		send_packet, NULL, NULL, NULL,
		THREAD_PRIORITY, 0, -1);


static const struct device *get_bme280_device(void)
{
	const struct device *const dev = DEVICE_DT_GET_ANY(bosch_bme280);

	if (dev == NULL) {
		/* No such node, or the node does not have status "okay". */
		LOG_ERR("Error: no device found.");
		return NULL;
	}

	if (!device_is_ready(dev)) {
		LOG_ERR("Error: Device \"%s\" is not ready; ", dev->name);
		return NULL;
	}

	LOG_INF("Found device \"%s\"", dev->name);
	return dev;
}

static int read_sensor_data(struct device *bme280, char *buffer, size_t buffer_size)
{
	int ret;
	struct sensor_value temp, press, humidity;

	ret = sensor_sample_fetch(bme280);
	if (ret < 0) {
		return ret;
	}

	sensor_channel_get(bme280, SENSOR_CHAN_AMBIENT_TEMP, &temp);
	sensor_channel_get(bme280, SENSOR_CHAN_PRESS, &press);
	sensor_channel_get(bme280, SENSOR_CHAN_HUMIDITY, &humidity);

	ret = snprintf(buffer, buffer_size,
				  	"Temp: %d.%06d; press: %d.%06d; humidity: %d.%06d\n",
				   	temp.val1, temp.val2, press.val1, press.val2,
					humidity.val1, humidity.val2);

	return ret;
}

static void quit(void)
{
	k_sem_give(&quit_lock);
}

static int sll_addr_from_str(struct sockaddr_ll *sll, const struct net_l2 *l2, const char *address)
{
	int ret;
#if defined(CONFIG_NET_L2_ETHERNET)
	if (l2 == &NET_L2_GET_NAME(ETHERNET)) {
		sll->sll_halen = sizeof(struct net_eth_addr);
		/* FIXME: assume IP data atm */
		sll->sll_protocol = htons(ETH_P_IP);
	}
#elif defined(CONFIG_NET_L2_IEEE802154)
	if (l2 == &NET_L2_GET_NAME(IEEE802154)) {
		sll->sll_halen = IEEE802154_SHORT_ADDR_LENGTH;
		sll->sll_protocol = htons(ETH_P_IEEE802154);
	}
#else
#error "No supported L2 enabled"
#endif

	ret = net_bytes_from_str(sll->sll_addr, sll->sll_halen, address);
	if (ret < 0) {
		LOG_ERR("Invalid MAC address '%s'", address);
	}

	return ret;
}

static int start_socket(int *sock)
{
	struct sockaddr_ll dst = { 0 };
	int ret;

	*sock = socket(AF_PACKET,
		       IS_ENABLED(CONFIG_NET_SAMPLE_ENABLE_PACKET_DGRAM) ?
							SOCK_DGRAM : SOCK_RAW,
		       ETH_P_ALL);
	if (*sock < 0) {
		LOG_ERR("Failed to create %s socket : %d",
			IS_ENABLED(CONFIG_NET_SAMPLE_ENABLE_PACKET_DGRAM) ?
							"DGRAM" : "RAW",
			errno);
		return -errno;
	}

	dst.sll_ifindex = net_if_get_by_iface(net_if_get_default());
	dst.sll_family = AF_PACKET;

	ret = bind(*sock, (const struct sockaddr *)&dst,
		   sizeof(struct sockaddr_ll));
	if (ret < 0) {
		LOG_ERR("Failed to bind packet socket : %d", errno);
		return -errno;
	}

	return 0;
}

static int recv_packet_socket(struct packet_data *packet)
{
	int ret = 0;
	int received;

	LOG_INF("Waiting for packets ...");

	do {
		if (finish) {
			ret = -1;
			break;
		}

		received = recv(packet->recv_sock, packet->recv_buffer,
				sizeof(packet->recv_buffer), 0);

		if (received < 0) {
			if (errno == EAGAIN) {
				continue;
			}

			LOG_ERR("RAW : recv error %d", errno);
			ret = -errno;
			break;
		}

		LOG_HEXDUMP_DBG(packet->recv_buffer, received, "recv");

	} while (true);

	return ret;
}

static void recv_packet(void)
{
	int ret;
	struct timeval timeo_optval = {
		.tv_sec = 1,
		.tv_usec = 0,
	};

	ret = start_socket(&packet.recv_sock);
	if (ret < 0) {
		quit();
		return;
	}

	ret = setsockopt(packet.recv_sock, SOL_SOCKET, SO_RCVTIMEO,
			 &timeo_optval, sizeof(timeo_optval));
	if (ret < 0) {
		quit();
		return;
	}

	while (ret == 0) {
		ret = recv_packet_socket(&packet);
		if (ret < 0) {
			quit();
			return;
		}
	}
}

static int send_packet_socket(struct packet_data *packet)
{
	struct sockaddr_ll dst = { 0 };
	struct net_if *iface;
	int ret;

	iface = net_if_get_default();
	dst.sll_ifindex = net_if_get_by_iface(iface);

	if (IS_ENABLED(CONFIG_NET_SAMPLE_ENABLE_PACKET_DGRAM)) {
		ret = sll_addr_from_str(&dst, net_if_l2(iface), CONFIG_NET_SAMPLE_DESTINATION_ADDR);
		if (ret < 0) {
			LOG_ERR("Failed to set destination address");
			return ret;
		}
	}

	while (!finish) {
		int len = strlen(buffer);
		if (bme280) {
			len = read_sensor_data(bme280, buffer, sizeof(buffer));
			if (len < 0) {
				LOG_ERR("Failed to read sensor data");
				return -1;
			}
		}

		ret = sendto(packet->send_sock, buffer, len, 0,
			     	 (const struct sockaddr *)&dst,
			     	 sizeof(struct sockaddr_ll));

		if (ret < 0) {
			LOG_ERR("Failed to send, errno %d", errno);
			break;
		}

		/* If we have received any data, flush it here in order to
		 * not to leak memory in IP stack.
		 */
		do {
			ret = recv(packet->send_sock, buffer, sizeof(buffer), MSG_DONTWAIT);
		} while (ret > 0);

		if (!FLOOD) {
			LOG_DBG("Sent %zd bytes", len);
			k_msleep(WAIT_TIME);
		}

	};

	return ret;
}

static void send_packet(void)
{
	int ret;

	ret = start_socket(&packet.send_sock);
	if (ret < 0) {
		quit();
		return;
	}

	while (ret == 0) {
		ret = send_packet_socket(&packet);
		if (ret < 0) {
			quit();
			return;
		}
	}
}

static void iface_up_handler(struct net_mgmt_event_callback *cb,
			     uint32_t mgmt_event, struct net_if *iface)
{
	if (mgmt_event == NET_EVENT_IF_UP) {
		k_sem_give(&iface_up);
	}
}

static void wait_for_interface(void)
{
	struct net_if *iface = net_if_get_default();
	struct net_mgmt_event_callback iface_up_cb;
	uint16_t pan_id = 0x1111;
	uint16_t channel = 15;
	uint16_t short_addr;
	uint8_t ext_addr[IEEE802154_MAX_ADDR_LENGTH];

	int ret;

	if (net_if_is_up(iface)) {
		return;
	}

	ret = net_mgmt(NET_REQUEST_IEEE802154_SET_CHANNEL, iface, &channel, sizeof(channel));
	if (ret) {
		NET_ERR("*** Failed to set channel\n");
	}

	ret = net_mgmt(NET_REQUEST_IEEE802154_SET_PAN_ID, iface, &pan_id, sizeof(pan_id));
	if (ret) {
		NET_ERR("*** Failed to set pan id\n");
	}

	ret = net_mgmt(NET_REQUEST_IEEE802154_GET_EXT_ADDR, iface, ext_addr, sizeof(ext_addr));
	if (ret) {
		NET_ERR("*** Failed to get extended address\n");
	}

	short_addr = ((uint16_t)ext_addr[6]) << 8 | ext_addr[7];

	ret = net_mgmt(NET_REQUEST_IEEE802154_SET_SHORT_ADDR, iface,
				   &short_addr, sizeof(short_addr));
	if (ret) {
		NET_ERR("*** Failed to set short addr\n");
	}

	// ret = net_mgmt(NET_REQUEST_IEEE802154_SET_ACK, iface, NULL, 0);
	// if (ret) {
	// 	NET_ERR("*** Failed to set ack request addr\n");
	// }

	net_mgmt_init_event_callback(&iface_up_cb, iface_up_handler, NET_EVENT_IF_UP);
	net_mgmt_add_event_callback(&iface_up_cb);

	if (net_if_up(iface)) {
		LOG_ERR("Failed to turn iface up");
		return;
	}

	/* Wait for the interface to come up. */
	k_sem_take(&iface_up, K_FOREVER);

	net_mgmt_del_event_callback(&iface_up_cb);
}

int main(void)
{

	k_sem_init(&quit_lock, 0, K_SEM_MAX_LIMIT);

	bme280 = get_bme280_device();

	LOG_INF("Waiting for interface");
	wait_for_interface();

	LOG_INF("Packet socket sample is running");

	k_thread_start(receiver_thread_id);
	k_thread_start(sender_thread_id);

	k_sem_take(&quit_lock, K_FOREVER);

	LOG_INF("Stopping...");

	finish = true;

	k_thread_join(receiver_thread_id, K_FOREVER);
	k_thread_join(sender_thread_id, K_FOREVER);

	if (packet.recv_sock >= 0) {
		(void)close(packet.recv_sock);
	}

	if (packet.send_sock >= 0) {
		(void)close(packet.send_sock);
	}
	return 0;
}