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
#include <zephyr/drivers/led_strip.h>

/* BME280 Environmental Sensor */
#define BME280_NODE DT_NODELABEL(bme280_sensor)
#if DT_NODE_EXISTS(BME280_NODE)
#include <bme280_shield.h>
#endif

#include <zephyr/net/socket.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/ieee802154.h>
#include <zephyr/net/ieee802154_mgmt.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/openthread.h>

#define STACK_SIZE 4096
#if defined(CONFIG_NET_TC_THREAD_COOPERATIVE)
#define THREAD_PRIORITY K_PRIO_COOP(CONFIG_NUM_COOP_PRIORITIES - 1)
#else
#define THREAD_PRIORITY K_PRIO_PREEMPT(8)
#endif
#define RECV_BUFFER_SIZE 128

#if DT_NODE_EXISTS(BME280_NODE)
static const struct device *bme280;
#endif

/* WS2812 LED Strip */
#define LED_STRIP_NODE DT_NODELABEL(led_strip)
#if DT_NODE_EXISTS(LED_STRIP_NODE)
#define LED_STRIP_SIZE DT_PROP(LED_STRIP_NODE, chain_length)
#define FILL_LED_STRIP(pixels, size, _r, _g, _b) \
do { \
	for (int i = 0; i < (size); i++) { \
		pixels[i].r = (_r); \
		pixels[i].g = (_g); \
		pixels[i].b = (_b); \
	} \
} while (0)

static const struct device *led_dev = DEVICE_DT_GET(LED_STRIP_NODE);
#endif

static struct k_sem quit_lock;
static bool finish;
static K_SEM_DEFINE(iface_up, 0, 1);


static void recv_packet(void);

K_THREAD_DEFINE(receiver_thread_id, STACK_SIZE,
		recv_packet, NULL, NULL, NULL,
		THREAD_PRIORITY, 0, -1);

#if DT_NODE_EXISTS(LED_STRIP_NODE)
static void update_led_strip(uint8_t position, uint8_t r, uint8_t g, uint8_t b)
{
	static struct led_rgb led_pixels[LED_STRIP_SIZE];

	if (!device_is_ready(led_dev)) {
		LOG_ERR("LED strip device not ready");
		return;
	}

	if (position < LED_STRIP_SIZE) {
		led_pixels[position].r = r;
		led_pixels[position].g = g;
		led_pixels[position].b = b;
	} else if (position == LED_STRIP_SIZE) {
		FILL_LED_STRIP(led_pixels, LED_STRIP_SIZE, r, g, b);
	} else {
		LOG_ERR("Invalid position: %d", position);
	}
	
	int ret = led_strip_update_rgb(led_dev, led_pixels, LED_STRIP_SIZE);
	if (ret < 0) {
		LOG_ERR("Failed to update LED strip: %d", ret);
	}
}
#endif


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
	int socket;


	struct timeval timeo_optval = {
		.tv_sec = 1,
		.tv_usec = 0,
	};

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(1234),
		.sin6_addr = in6addr_any,
	};

	socket = create_datagram_socket((const struct sockaddr *)&addr, sizeof(addr));
	if (socket < 0) {
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
	char buffer[RECV_BUFFER_SIZE];
	struct sockaddr src_addr;
	socklen_t addrlen = sizeof(src_addr);

	while (ret >= 0) {
		received = recvfrom(socket, buffer,	sizeof(buffer) - 1, 0, &src_addr, &addrlen);

		if (received > 0) {
			/* Null-terminate the received data for string operations */
			buffer[received] = '\0';
			
			print_address(src_addr.sa_family, &src_addr);
			LOG_HEXDUMP_DBG(buffer, received, "Data:");

			len = 0;

			if (strncmp(buffer, "led:", 4) == 0) {
#if DT_NODE_EXISTS(LED_STRIP_NODE)				
				uint8_t r, g, b;
				if (sscanf(buffer, "led:%hhu,%hhu,%hhu", &r, &g, &b) == 3) {
					update_led_strip(LED_STRIP_SIZE, r, g, b);
				} else {
					LOG_ERR("Invalid LED command: %s", buffer);
				}
#endif
			} else if (strncmp(buffer, "temp", 4) == 0) {
#if DT_NODE_EXISTS(BME280_NODE)
				if (bme280) {
					len = bme280_shield_read_sensor_data(bme280, buffer, sizeof(buffer));
				} else {
					LOG_ERR("BME280 not found");
				}
#endif
			} else {
				len = snprintf(buffer, sizeof(buffer), "Hello from Zephyr!\n");
			}

			if (len) {
				ret = sendto(socket, buffer, len, 0, &src_addr, addrlen);
				if (ret < 0) {
					LOG_ERR("Failed to send, errno %d", errno);
				}
			}
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

int main(void)
{
	k_sem_init(&quit_lock, 0, K_SEM_MAX_LIMIT);

#if DT_NODE_EXISTS(BME280_NODE)
	bme280 = bme280_shield_get_device();
#endif
	
#if DT_NODE_EXISTS(LED_STRIP_NODE)
	if (device_is_ready(led_dev)) {
		struct led_rgb led_pixels[LED_STRIP_SIZE];
		FILL_LED_STRIP(led_pixels, LED_STRIP_SIZE, 0, 0, 20);
		led_strip_update_rgb(led_dev, led_pixels, LED_STRIP_SIZE);
	} else {
		LOG_WRN("LED strip device not ready");
	}
#endif

	k_thread_start(receiver_thread_id);
	openthread_run();

	k_sem_take(&quit_lock, K_FOREVER);

	LOG_INF("Stopping...");

	finish = true;

	k_thread_join(receiver_thread_id, K_FOREVER);

	return 0;
}
