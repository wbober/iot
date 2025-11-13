/*
 * Copyright (c) 2024
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BME280_SHIELD_H
#define BME280_SHIELD_H

#include <zephyr/device.h>
#include <zephyr/drivers/sensor.h>
#include <stddef.h>

/**
 * @brief Get the BME280 device instance
 * 
 * This function retrieves the BME280 sensor device instance.
 * 
 * @return Pointer to the BME280 device, or NULL if not found or not ready
 */
const struct device *bme280_shield_get_device(void);

/**
 * @brief Read sensor data from BME280 and format as string
 * 
 * Reads temperature, pressure, and humidity from the BME280 sensor
 * and formats the data as a human-readable string.
 * 
 * @param dev         Pointer to the BME280 device
 * @param buffer      Buffer to store the formatted string
 * @param buffer_size Size of the buffer
 * 
 * @return Number of characters written (excluding null terminator), 
 *         or negative error code on failure
 */
int bme280_shield_read_sensor_data(const struct device *dev, 
                                    char *buffer, 
                                    size_t buffer_size);

/**
 * @brief Read raw sensor values from BME280
 * 
 * Reads temperature, pressure, and humidity from the BME280 sensor.
 * 
 * @param dev       Pointer to the BME280 device
 * @param temp      Pointer to store temperature value
 * @param press     Pointer to store pressure value
 * @param humidity  Pointer to store humidity value
 * 
 * @return 0 on success, negative error code on failure
 */
int bme280_shield_read_values(const struct device *dev,
                               struct sensor_value *temp,
                               struct sensor_value *press,
                               struct sensor_value *humidity);

#endif /* BME280_SHIELD_H */
