# WS2812 LED Strip Shield

This shield adds support for WS2812 RGB LED strips using I2S for communication with nRF52840DK and nRF5340DK boards.

## Hardware Setup

The WS2812 LED strip should be connected to the following pins on the nRF52840DK:

- Data: P1.07 (I2S_SDOUT)
- Power: 5V (for 5V strips) or 3.3V (for 3.3V strips)
- Ground: GND

## Software Setup

There are multiple ways to enable this shield in your project:

### Method 1: Using west build command line

```bash
# Building with the shield
west build -b nrf52840dk_nrf52840 -- -DSHIELD=ws2812_shield

# Building without the shield
west build -b nrf52840dk_nrf52840
```

### Method 2: Using CMakeLists.txt

Add the following to your project's CMakeLists.txt:

```cmake
# Add custom shields directory to the board root
list(APPEND BOARD_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Optional: Set the shield 
set(SHIELD ws2812_shield)
```

### Method 3: Using a .conf overlay file

Create a file named `<your_project_name>.conf` with:

```
CONFIG_SHIELD_WS2812_SHIELD=y
```

## Conditional Code for Shield Detection

Your application code can check if the shield is present using device tree macros:

```c
#include <zephyr/kernel.h>
#include <zephyr/drivers/led_strip.h>

#define LED_STRIP_NODE DT_NODELABEL(led_strip)

#if DT_NODE_EXISTS(LED_STRIP_NODE)
#define LED_STRIP_SIZE DT_PROP(LED_STRIP_NODE, chain_length)
static const struct device *led_dev = DEVICE_DT_GET(LED_STRIP_NODE);
static struct led_rgb led_pixels[LED_STRIP_SIZE];
#endif

int main(void) {
#if DT_NODE_EXISTS(LED_STRIP_NODE)
    if (!device_is_ready(led_dev)) {
        return -1;
    }
    
    // Clear all pixels
    memset(led_pixels, 0, sizeof(led_pixels));
    
    // Set first pixel to red
    led_pixels[0].r = 255;
    led_pixels[0].g = 0;
    led_pixels[0].b = 0;
    
    led_strip_update_rgb(led_dev, led_pixels, LED_STRIP_SIZE);
#endif
    
    return 0;
}
```

## Supported Features

- Control of WS2812/WS2812B LED strips
- Up to 9 RGB LEDs by default (configurable via chain-length property)
- Full RGB color control
- Compatible with both nRF52840DK and nRF5340DK boards

## Dependencies

This shield requires the following Zephyr options to be enabled:

- CONFIG_I2S
- CONFIG_LED_STRIP
- CONFIG_WS2812_STRIP_I2S
