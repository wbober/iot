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
#include <zephyr/net/openthread.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_link_format.h>

#include <zephyr/shell/shell.h>

#define STACK_SIZE 4096
#define MAX_MSG_LEN 256
#define UDP_PORT 5683

#if defined(CONFIG_NET_TC_THREAD_COOPERATIVE)
#define THREAD_PRIORITY K_PRIO_COOP(CONFIG_NUM_COOP_PRIORITIES - 1)
#else
#define THREAD_PRIORITY K_PRIO_PREEMPT(8)
#endif

#define COAP_PATH(...) ((const char * const[]) {__VA_ARGS__, NULL})

static struct k_sem quit_lock;
int sock;

static const struct device *bme280;
static struct coap_resource coap_resources[];
static struct coap_reply coap_replies[3];

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
	uint8_t data[MAX_MSG_LEN];
	int r;

	r = coap_well_known_core_get(resource, request, &response,
				     data, MAX_MSG_LEN);
	if (r < 0) {
		return r;
	}

	return send_coap_reply(&response, addr, addr_len);
}

static int piggyback_get(struct coap_resource *resource,
			 			 struct coap_packet *request,
			 			 struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_packet response;
	uint8_t payload[MAX_MSG_LEN] = "test";
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t data[MAX_MSG_LEN];
	uint16_t id;
	uint8_t code;
	uint8_t type;
	uint8_t tkl;
	int r;

	code = coap_header_get_code(request);
	type = coap_header_get_type(request);
	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	if (type == COAP_TYPE_CON) {
		type = COAP_TYPE_ACK;
	} else {
		type = COAP_TYPE_NON_CON;
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

	r = read_sensor_data((struct device *)bme280, (char *)payload, sizeof(payload));
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
	return r;
}

int print_reply(const struct coap_packet *response,
			    	   struct coap_reply *reply,
			   		   const struct sockaddr *from) {
	uint8_t *payload;
	uint16_t payload_len;
	payload = coap_packet_get_payload(response, &payload_len);
	LOG_HEXDUMP_INF(payload, payload_len, "CoAP data: ");

	return 0;
}

static void process_coap_message(uint8_t *data, uint16_t data_len,
				 struct sockaddr *client_addr,
				 socklen_t client_addr_len)
{
	struct coap_packet packet;
	struct coap_reply *reply;
	struct coap_option options[16] = { 0 };
	uint8_t opt_num = 16U;
	uint16_t id;
	uint8_t code;
	uint8_t type;
	uint8_t tkl;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	int r;

	r = coap_packet_parse(&packet, data, data_len, options, opt_num);
	if (r < 0) {
		LOG_ERR("Invalid data received (%d)\n", r);
		return;
	}

	code = coap_header_get_code(&packet);
	type = coap_header_get_type(&packet);
	id = coap_header_get_id(&packet);
	tkl = coap_header_get_token(&packet, token);

	LOG_INF("CoAP message received");
	LOG_INF("type: %u code %u id %u", type, code, id);
	LOG_HEXDUMP_INF(token, tkl, "token: ");

	reply = coap_response_received(&packet, client_addr, coap_replies,
				  			   		ARRAY_SIZE(coap_replies));
	if (reply) {
		coap_reply_clear(reply);
		return;
	}

	r = coap_handle_request(&packet, coap_resources, options, opt_num,
							client_addr, client_addr_len);
	if (r < 0) {
		LOG_WRN("No handler for such request (%d)\n", r);
	}
}

static int create_datagram_sock(const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;
	int sock;

	sock = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create sock: %d", errno);
		return -errno;
	}

	ret = bind(sock, addr, addrlen);
	if (ret < 0) {
		LOG_ERR("Failed to bind packet sock : %d", errno);
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
	int received;
	char buffer[MAX_MSG_LEN];
	struct sockaddr src_addr;
	socklen_t addrlen = sizeof(src_addr);

	struct timeval timeo_optval = {
		.tv_sec = 1,
		.tv_usec = 0,
	};

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(UDP_PORT),
		.sin6_addr = in6addr_any,
	};

	sock = create_datagram_sock((const struct sockaddr *)&addr, sizeof(addr));
	if (sock < 0) {
		return;
	}

	ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeo_optval, sizeof(timeo_optval));
	if (ret < 0) {
		return;
	}

	while (ret >= 0) {
		received = recvfrom(sock, buffer,sizeof(buffer), 0, &src_addr, &addrlen);
		if (received > 0) {
			print_address(src_addr.sa_family, &src_addr);
			process_coap_message(buffer, received, &src_addr, addrlen);
		} else if (errno != EAGAIN) {
			LOG_ERR("RAW : recv error %d", errno);
			ret = -errno;
		}
	}

	close(sock);
}

static struct coap_resource coap_resources[] = {
	{ .get = well_known_core_get,
	  .path = COAP_WELL_KNOWN_CORE_PATH,
	},
	{ .get = piggyback_get,
	  .path = COAP_PATH("sensor")
	},
	{ },
};

static int coap_get_cmd(const struct shell *sh,
                        size_t argc, char **argv, void *data)
{
	struct sockaddr address;
	struct coap_packet request;
	uint8_t packet[MAX_MSG_LEN];
	int r;

	if (net_addr_pton(AF_INET6, argv[1], &net_sin6(&address)->sin6_addr) != 0) {
		LOG_ERR("Invalid address");
		return -EINVAL;
	};
	net_sin6(&address)->sin6_port = htons(UDP_PORT);

	r = coap_packet_init(&request, packet, sizeof(packet),
			 				1, COAP_TYPE_NON_CON, 8, coap_next_token(),
							COAP_METHOD_GET, coap_next_id());

	if (r < 0) {
		LOG_ERR("Failed to init CoAP message");
		return r;
	}

	/* Append options */
	coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
							  argv[2], strlen(argv[2]));


	struct coap_reply *reply = coap_reply_next_unused(coap_replies,
													  ARRAY_SIZE(coap_replies));
	coap_reply_init(reply, &request);
	reply->reply = print_reply;

	r = sendto(sock, request.data, request.offset, 0, &address, sizeof(address));
	if (r < 0) {
		LOG_ERR("Failed to send %d", errno);
		r = -errno;
	}

	return r;
}

SHELL_CMD_REGISTER(coap_get, NULL, "CoAP GET", coap_get_cmd);

int main(void)
{
	k_sem_init(&quit_lock, 0, K_SEM_MAX_LIMIT);

	bme280 = get_bme280_device();

	k_thread_start(receiver_thread_id);
	openthread_start(openthread_get_default_context());

	k_sem_take(&quit_lock, K_FOREVER);

	LOG_INF("Stopping...");

	k_thread_join(receiver_thread_id, K_FOREVER);

	return 0;
}