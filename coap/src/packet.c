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
#include <zephyr/net/net_ip.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_link_format.h>


#define STACK_SIZE 4096
#if defined(CONFIG_NET_TC_THREAD_COOPERATIVE)
#define THREAD_PRIORITY K_PRIO_COOP(CONFIG_NUM_COOP_PRIORITIES - 1)
#else
#define THREAD_PRIORITY K_PRIO_PREEMPT(8)
#endif

#define MAX_MSG_LEN 256
#define UDP_PORT 5683

static struct k_sem quit_lock;
static bool finish;
static K_SEM_DEFINE(iface_up, 0, 1);
int socket;
static const struct device *bme280;

#define NUM_PENDINGS 10
static struct coap_pending pendings[NUM_PENDINGS];

static void recv_packet(void);

K_THREAD_DEFINE(receiver_thread_id, STACK_SIZE,
		recv_packet, NULL, NULL, NULL,
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

static int send_coap_reply(struct coap_packet *cpkt,
			   const struct sockaddr *addr,
			   socklen_t addr_len)
{
	int r;

	net_hexdump("Response", cpkt->data, cpkt->offset);

	r = sendto(sock, cpkt->data, cpkt->offset, 0, addr, addr_len);
	if (r < 0) {
		LOG_ERR("Failed to send %d", errno);
		r = -errno;
	}

	return r;
}

static int well_known_core_get(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_packet response;
	uint8_t *data;
	int r;

	data = (uint8_t *)k_malloc(MAX_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_well_known_core_get(resource, request, &response,
				     data, MAX_MSG_LEN);
	if (r < 0) {
		goto end;
	}

	r = send_coap_reply(&response, addr, addr_len);

end:
	k_free(data);

	return r;
}

static int piggyback_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_packet response;
	uint8_t payload[40];
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t *data;
	uint16_t id;
	uint8_t code;
	uint8_t type;
	uint8_t tkl;
	int r;

	code = coap_header_get_code(request);
	type = coap_header_get_type(request);
	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	LOG_INF("*******");
	LOG_INF("type: %u code %u id %u", type, code, id);
	LOG_INF("*******");

	if (type == COAP_TYPE_CON) {
		type = COAP_TYPE_ACK;
	} else {
		type = COAP_TYPE_NON_CON;
	}

	data = (uint8_t *)k_malloc(MAX_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_packet_init(&response, data, MAX_MSG_LEN,
			     COAP_VERSION_1, type, tkl, token,
			     COAP_RESPONSE_CODE_CONTENT, id);
	if (r < 0) {
		goto end;
	}

	r = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT,
				   COAP_CONTENT_FORMAT_TEXT_PLAIN);
	if (r < 0) {
		goto end;
	}

	r = coap_packet_append_payload_marker(&response);
	if (r < 0) {
		goto end;
	}

	/* The response that coap-client expects */
	r = snprintk((char *) payload, sizeof(payload),
		     "Type: %u\nCode: %u\nMID: %u\n", type, code, id);
	if (r < 0) {
		goto end;
	}

	r = coap_packet_append_payload(&response, (uint8_t *)payload,
				       strlen(payload));
	if (r < 0) {
		goto end;
	}

	r = send_coap_reply(&response, addr, addr_len);

end:
	k_free(data);

	return r;
}

static void process_coap_request(uint8_t *data, uint16_t data_len,
				 struct sockaddr *client_addr,
				 socklen_t client_addr_len)
{
	struct coap_packet request;
	struct coap_pending *pending;
	struct coap_option options[16] = { 0 };
	uint8_t opt_num = 16U;
	uint8_t type;
	int r;

	r = coap_packet_parse(&request, data, data_len, options, opt_num);
	if (r < 0) {
		LOG_ERR("Invalid data received (%d)\n", r);
		return;
	}

	type = coap_header_get_type(&request);

	pending = coap_pending_received(&request, pendings, NUM_PENDINGS);
	if (!pending) {
		goto not_found;
	}

	/* Clear CoAP pending request */
	if (type == COAP_TYPE_ACK || type == COAP_TYPE_RESET) {
		k_free(pending->data);
		coap_pending_clear(pending);

		// if (type == COAP_TYPE_RESET) {
		// 	remove_observer(client_addr);
		// }
	}

	return;

not_found:
	r = coap_handle_request(&request, coap_resources, options, opt_num,
				client_addr, client_addr_len);
	if (r < 0) {
		LOG_WRN("No handler for such request (%d)\n", r);
	}
}

static void quit(void)
{
	k_sem_give(&quit_lock);
}

static int create_datagram_socket(const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;
	int sock;

	sock = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create socket: %d", errno);
		return -errno;
	}

	ret = bind(sock, addr, addrlen);
	if (ret < 0) {
		LOG_ERR("Failed to bind packet socket : %d", errno);
		return -errno;
	}

	return sock;
}

static void print_address(sa_family_t af, struct sockaddr *addr)
{
	char buf[NET_IPV6_ADDR_LEN];
	switch (af) {
		case AF_INET6:
			net_addr_ntop(af, &net_sin6(addr)->sin6_addr, buf, NET_IPV6_ADDR_LEN);
			break;
	}
	LOG_INF("Peer %s", buf);
}

static void recv_packet(void)
{
	int ret;

	struct timeval timeo_optval = {
		.tv_sec = 1,
		.tv_usec = 0,
	};

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(UDP_PORT),
		.sin6_addr = in6addr_any,
	};

	socket = create_datagram_socket((const struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		quit();
		return;
	}

	ret = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeo_optval, sizeof(timeo_optval));
	if (ret < 0) {
		quit();
		return;
	}

	int received;
	int len;
	char buffer[MAX_MSG_LEN];
	struct sockaddr src_addr;
	socklen_t addrlen = sizeof(src_addr);

	while (ret >= 0) {
		received = recvfrom(socket, buffer,sizeof(buffer), 0, &src_addr, &addrlen);
		if (received > 0) {
			print_address(src_addr.sa_family, &src_addr);
			LOG_HEXDUMP_DBG(buffer, received, "Data:");

			process_coap_request(buffer, received, &src_addr, addrlen)

		} else if (errno != EAGAIN) {
			LOG_ERR("RAW : recv error %d", errno);
			ret = -errno;
		}
	}

	close(socket);
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

	if (net_if_is_up(iface)) {
		return;
	}

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


#define COAP_PATH(...) \
	((const char * const[]) {__VA_ARGS__, NULL })

static struct coap_resource coap_resources[] = {
	{ .get = well_known_core_get,
	  .path = COAP_WELL_KNOWN_CORE_PATH,
	},
	{ .get = piggyback_get,
	  .path = COAP_PATH("sensor")
	},
	{ },
};

int main(void)
{
	k_sem_init(&quit_lock, 0, K_SEM_MAX_LIMIT);

	bme280 = get_bme280_device();

	k_thread_start(receiver_thread_id);
	openthread_start(openthread_get_default_context());

	k_sem_take(&quit_lock, K_FOREVER);

	LOG_INF("Stopping...");

	finish = true;

	k_thread_join(receiver_thread_id, K_FOREVER);

	return 0;
}