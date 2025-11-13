# Copyright (c) 2024
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_SHIELD_BME280_SHIELD)
  zephyr_include_directories(.)
  zephyr_library_sources(bme280_shield.c)
endif()
