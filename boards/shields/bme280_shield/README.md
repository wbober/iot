# BME280 Environmental Sensor Shield

This shield adds support for the Bosch BME280 environmental sensor (temperature, pressure, and humidity) connected via I2C.

## Hardware Setup

The BME280 sensor should be connected to the Arduino I2C bus on your board:

- SDA: Arduino I2C SDA pin
- SCL: Arduino I2C SCL pin  
- VCC: 3.3V
- GND: Ground

**I2C Address**: The default address is 0x76. If your BME280 uses address 0x77, modify the `reg` property in `bme280_shield.overlay`.

## Software Setup

### Method 1: Using west build command line

```bash
# Building with the shield
west build -b nrf52840dk_nrf52840 -- -DSHIELD=bme280_shield

# Building without the shield
west build -b nrf52840dk_nrf52840
```

### Method 2: Using CMakeLists.txt

Add the following to your project's CMakeLists.txt before `find_package(Zephyr)`:

```cmake
# Add custom shields directory to the board root
list(APPEND BOARD_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
```

## API Usage

Include the shield header in your application:

```c
#include <bme280_shield.h>

int main(void) {
    const struct device *bme280;
    char buffer[128];
    
    // Get the BME280 device
    bme280 = bme280_shield_get_device();
    if (!bme280) {
        printk("BME280 not available\n");
        return -1;
    }
    
    // Read sensor data as formatted string
    int len = bme280_shield_read_sensor_data(bme280, buffer, sizeof(buffer));
    if (len > 0) {
        printk("%s", buffer);
    }
    
    // Or read raw sensor values
    struct sensor_value temp, press, humidity;
    if (bme280_shield_read_values(bme280, &temp, &press, &humidity) == 0) {
        printk("Temperature: %d.%06d C\n", temp.val1, temp.val2);
        printk("Pressure: %d.%06d kPa\n", press.val1, press.val2);
        printk("Humidity: %d.%06d %%\n", humidity.val1, humidity.val2);
    }
    
    return 0;
}
```

## Conditional Code for Shield Detection

Your application can check if the shield is present at compile time:

```c
#ifdef CONFIG_SHIELD_BME280_SHIELD
    #include <bme280_shield.h>
    // BME280-specific code
#endif
```

Or check at runtime:

```c
const struct device *bme280 = bme280_shield_get_device();
if (bme280) {
    // Use BME280
}
```

## Supported Features

- Temperature measurement (-40 to +85°C)
- Pressure measurement (300 to 1100 hPa)
- Humidity measurement (0 to 100% RH)
- I2C interface

## Dependencies

This shield automatically enables the following Zephyr options:

- CONFIG_I2C
- CONFIG_SENSOR
- CONFIG_BME280
