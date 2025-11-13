/*
 * Copyright (c) 2024
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bme280_shield.h"
#include <zephyr/logging/log.h>
#include <zephyr/devicetree.h>
#include <stdio.h>

LOG_MODULE_REGISTER(bme280_shield, LOG_LEVEL_INF);

#define BME280_NODE DT_NODELABEL(bme280_sensor)

const struct device *bme280_shield_get_device(void)
{
#if DT_NODE_EXISTS(BME280_NODE)
	const struct device *const dev = DEVICE_DT_GET(BME280_NODE);

	if (!device_is_ready(dev)) {
		LOG_ERR("BME280 device %s is not ready", dev->name);
		return NULL;
	}

	LOG_INF("Found BME280 device: %s", dev->name);
	return dev;
#else
	LOG_ERR("BME280 sensor node not found in devicetree");
	return NULL;
#endif
}

int bme280_shield_read_values(const struct device *dev,
                               struct sensor_value *temp,
                               struct sensor_value *press,
                               struct sensor_value *humidity)
{
	int ret;

	if (dev == NULL) {
		return -EINVAL;
	}

	ret = sensor_sample_fetch(dev);
	if (ret < 0) {
		LOG_ERR("Failed to fetch sensor sample: %d", ret);
		return ret;
	}

	ret = sensor_channel_get(dev, SENSOR_CHAN_AMBIENT_TEMP, temp);
	if (ret < 0) {
		LOG_ERR("Failed to get temperature: %d", ret);
		return ret;
	}

	ret = sensor_channel_get(dev, SENSOR_CHAN_PRESS, press);
	if (ret < 0) {
		LOG_ERR("Failed to get pressure: %d", ret);
		return ret;
	}

	ret = sensor_channel_get(dev, SENSOR_CHAN_HUMIDITY, humidity);
	if (ret < 0) {
		LOG_ERR("Failed to get humidity: %d", ret);
		return ret;
	}

	return 0;
}

int bme280_shield_read_sensor_data(const struct device *dev,
                                    char *buffer,
                                    size_t buffer_size)
{
	struct sensor_value temp, press, humidity;
	int ret;

	ret = bme280_shield_read_values(dev, &temp, &press, &humidity);
	if (ret < 0) {
		return ret;
	}

	ret = snprintf(buffer, buffer_size,
	               "Temp: %d.%06d; press: %d.%06d; humidity: %d.%06d\n",
	               temp.val1, temp.val2, press.val1, press.val2,
	               humidity.val1, humidity.val2);

	return ret;
}
