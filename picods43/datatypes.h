#ifndef FIRMWARE_DATATYPES_H
#define FIRMWARE_DATATYPES_H

#include <stdint.h>
#include <stdbool.h>

// Type Defines
// Enumeration for joystick buttons.
typedef enum {
    SWITCH_Y       = 0x01,
    SWITCH_B       = 0x02,
    SWITCH_A       = 0x04,
    SWITCH_X       = 0x08,
    SWITCH_L       = 0x10,
    SWITCH_R       = 0x20,
    SWITCH_ZL      = 0x40,
    SWITCH_ZR      = 0x80,
    SWITCH_MINUS   = 0x100,
    SWITCH_PLUS    = 0x200,
    SWITCH_LCLICK  = 0x400,
    SWITCH_RCLICK  = 0x800,
    SWITCH_HOME    = 0x1000,
    SWITCH_CAPTURE = 0x2000,
} JoystickButtons_t;

// Battery levels
#define BATTERY_FULL        0x08
#define BATTERY_MEDIUM      0x06
#define BATTERY_LOW         0x04
#define BATTERY_CRITICAL    0x02
#define BATTERY_EMPTY       0x00
#define BATTERY_CHARGING    0x01 // Can be OR'ed

// DPAD values
#define HAT_TOP          0x00
#define HAT_TOP_RIGHT    0x01
#define HAT_RIGHT        0x02
#define HAT_BOTTOM_RIGHT 0x03
#define HAT_BOTTOM       0x04
#define HAT_BOTTOM_LEFT  0x05
#define HAT_LEFT         0x06
#define HAT_TOP_LEFT     0x07
#define HAT_CENTER       0x08

// Analog sticks
#define STICK_MIN      0
#define STICK_CENTER 128
#define STICK_MAX    255

// https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/master/bluetooth_hid_subcommands_notes.md
typedef enum {
    SUBCOMMAND_CONTROLLER_STATE_ONLY        = 0x00,
    SUBCOMMAND_BLUETOOTH_MANUAL_PAIRING     = 0x01,
    SUBCOMMAND_REQUEST_DEVICE_INFO          = 0x02,
    SUBCOMMAND_SET_INPUT_REPORT_MODE        = 0x03,
    SUBCOMMAND_TRIGGER_BUTTONS_ELAPSED_TIME = 0x04,
    SUBCOMMAND_GET_PAGE_LIST_STATE          = 0x05,
    SUBCOMMAND_SET_HCI_STATE                = 0x06,
    SUBCOMMAND_RESET_PAIRING_INFO           = 0x07,
    SUBCOMMAND_SET_SHIPMENT_LOW_POWER_STATE = 0x08,
    SUBCOMMAND_SPI_FLASH_READ               = 0x10,
    SUBCOMMAND_SPI_FLASH_WRITE              = 0x11,
    SUBCOMMAND_SPI_SECTOR_ERASE             = 0x12,
    SUBCOMMAND_RESET_NFC_IR_MCU             = 0x20,
    SUBCOMMAND_SET_NFC_IR_MCU_CONFIG        = 0x21,
    SUBCOMMAND_SET_NFC_IR_MCU_STATE         = 0x22,
    SUBCOMMAND_SET_PLAYER_LIGHTS            = 0x30,
    SUBCOMMAND_GET_PLAYER_LIGHTS            = 0x31,
    SUBCOMMAND_SET_HOME_LIGHTS              = 0x38,
    SUBCOMMAND_ENABLE_IMU                   = 0x40,
    SUBCOMMAND_SET_IMU_SENSITIVITY          = 0x41,
    SUBCOMMAND_WRITE_IMU_REGISTERS          = 0x42,
    SUBCOMMAND_READ_IMU_REGISTERS           = 0x43,
    SUBCOMMAND_ENABLE_VIBRATION             = 0x48,
    SUBCOMMAND_GET_REGULATED_VOLTAGE        = 0x50,
} Switch_Subcommand_t;

// https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/master/spi_flash_notes.md
typedef enum {
    ADDRESS_SERIAL_NUMBER         = 0x6000,
    ADDRESS_CONTROLLER_COLOR      = 0x6050,
    ADDRESS_FACTORY_PARAMETERS_1  = 0x6080,
    ADDRESS_FACTORY_PARAMETERS_2  = 0x6098,
    ADDRESS_FACTORY_CALIBRATION_1 = 0x6020,
    ADDRESS_FACTORY_CALIBRATION_2 = 0x603D,
    ADDRESS_STICKS_CALIBRATION    = 0x8010,
    ADDRESS_IMU_CALIBRATION       = 0x8028,
} SPI_Address_t;

// Standard input report sent to Switch (doesn't contain IMU data)
// Note that compilers can align and order bits in every byte however they want (endianness)
// Taken from https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/master/bluetooth_hid_notes.md#standard-input-report-format
// The order in every byte is inverted

typedef struct {
    uint8_t connection_info: 4;
    uint8_t battery_level: 4;
    bool button_y: 1;
    bool button_x: 1;
    bool button_b: 1;
    bool button_a: 1;
    bool button_right_sr: 1;
    bool button_right_sl: 1;
    bool button_r: 1;
    bool button_zr: 1;
    bool button_minus: 1;
    bool button_plus: 1;
    bool button_thumb_r: 1;
    bool button_thumb_l: 1;
    bool button_home: 1;
    bool button_capture: 1;
    uint8_t dummy: 1;
    bool charging_grip: 1;
    bool dpad_down: 1;
    bool dpad_up: 1;
    bool dpad_right: 1;
    bool dpad_left: 1;
    bool button_left_sr: 1;
    bool button_left_sl: 1;
    bool button_l: 1;
    bool button_zl: 1;
    uint8_t analog[6];
    uint8_t vibrator_input_report;
} __attribute__((packed)) USB_StandardReport_t;

// Full (extended) input report sent to Switch, with IMU data
typedef struct {
    USB_StandardReport_t standardReport;
    int16_t imu[3 * 2 * 3]; // each axis is uint16_t, 3 axis per sensor, 2 sensors (accel and gyro), 3 reports
} __attribute__((packed)) USB_ExtendedReport_t;

typedef struct {
  //uint8_t pcode;
  uint8_t cont1;
  uint8_t un1;
  uint8_t cont2;
  uint8_t un2;
  uint8_t un3;
  uint8_t smallRumble;
  uint8_t largeRumble;
  uint8_t r;
  uint8_t g;
  uint8_t b;
  uint8_t flashOn;
  uint8_t flashOff;  // Time to flash bright/dark (255 = 2.5 seconds)
  uint8_t un4[8];
  uint8_t vl;
  uint8_t vr;
  uint8_t vm;
  uint8_t vs;
  uint8_t data[49];
  uint32_t crc;
} __attribute__((packed)) ps4_cmd_t;

typedef struct {
    uint8_t mt;
    uint8_t tt;
    uint8_t fs;
    uint8_t un1;
    uint8_t un2;
    uint8_t smallRumble;
    uint8_t largeRumble;
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t flashOn;
    uint8_t flashOff;
    uint8_t un3[8];
    uint8_t vl;
    uint8_t vr;
    uint8_t vm;
    uint8_t vs;
    uint8_t un4;
    uint8_t un5[52];
    uint16_t afc;
    uint8_t ah;
    uint8_t bsbc[249];
    uint32_t crc;
} __attribute__((packed)) ps4_cmd2_t;

const uint8_t hid_report_descriptor[203] = {
    0x05, 0x01,        // Usage Page (Generic Desktop Ctrls)
    0x15, 0x00,        // Logical Minimum (0)
    0x09, 0x04,        // Usage (Joystick)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x30,        //   Report ID (48)
    0x05, 0x01,        //   Usage Page (Generic Desktop Ctrls)
    0x05, 0x09,        //   Usage Page (Button)
    0x19, 0x01,        //   Usage Minimum (0x01)
    0x29, 0x0A,        //   Usage Maximum (0x0A)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x01,        //   Logical Maximum (1)
    0x75, 0x01,        //   Report Size (1)
    0x95, 0x0A,        //   Report Count (10)
    0x55, 0x00,        //   Unit Exponent (0)
    0x65, 0x00,        //   Unit (None)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x05, 0x09,        //   Usage Page (Button)
    0x19, 0x0B,        //   Usage Minimum (0x0B)
    0x29, 0x0E,        //   Usage Maximum (0x0E)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x01,        //   Logical Maximum (1)
    0x75, 0x01,        //   Report Size (1)
    0x95, 0x04,        //   Report Count (4)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x01,        //   Report Size (1)
    0x95, 0x02,        //   Report Count (2)
    0x81, 0x03,        //   Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x0B, 0x01, 0x00, 0x01, 0x00,  //   Usage (0x010001)
    0xA1, 0x00,        //   Collection (Physical)
    0x0B, 0x30, 0x00, 0x01, 0x00,  //     Usage (0x010030)
    0x0B, 0x31, 0x00, 0x01, 0x00,  //     Usage (0x010031)
    0x0B, 0x32, 0x00, 0x01, 0x00,  //     Usage (0x010032)
    0x0B, 0x35, 0x00, 0x01, 0x00,  //     Usage (0x010035)
    0x15, 0x00,        //     Logical Minimum (0)
    0x27, 0xFF, 0xFF, 0x00, 0x00,  //     Logical Maximum (65534)
    0x75, 0x10,        //     Report Size (16)
    0x95, 0x04,        //     Report Count (4)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              //   End Collection
    0x0B, 0x39, 0x00, 0x01, 0x00,  //   Usage (0x010039)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x07,        //   Logical Maximum (7)
    0x35, 0x00,        //   Physical Minimum (0)
    0x46, 0x3B, 0x01,  //   Physical Maximum (315)
    0x65, 0x14,        //   Unit (System: English Rotation, Length: Centimeter)
    0x75, 0x04,        //   Report Size (4)
    0x95, 0x01,        //   Report Count (1)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x05, 0x09,        //   Usage Page (Button)
    0x19, 0x0F,        //   Usage Minimum (0x0F)
    0x29, 0x12,        //   Usage Maximum (0x12)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x01,        //   Logical Maximum (1)
    0x75, 0x01,        //   Report Size (1)
    0x95, 0x04,        //   Report Count (4)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x34,        //   Report Count (52)
    0x81, 0x03,        //   Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x06, 0x00, 0xFF,  //   Usage Page (Vendor Defined 0xFF00)
    0x85, 0x21,        //   Report ID (33)
    0x09, 0x01,        //   Usage (0x01)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x3F,        //   Report Count (63)
    0x81, 0x03,        //   Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x85, 0x81,        //   Report ID (-127)
    0x09, 0x02,        //   Usage (0x02)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x3F,        //   Report Count (63)
    0x81, 0x03,        //   Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x85, 0x01,        //   Report ID (1)
    0x09, 0x03,        //   Usage (0x03)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x3F,        //   Report Count (63)
    0x91, 0x83,        //   Output (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Volatile)
    0x85, 0x10,        //   Report ID (16)
    0x09, 0x04,        //   Usage (0x04)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x3F,        //   Report Count (63)
    0x91, 0x83,        //   Output (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Volatile)
    0x85, 0x80,        //   Report ID (-128)
    0x09, 0x05,        //   Usage (0x05)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x3F,        //   Report Count (63)
    0x91, 0x83,        //   Output (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Volatile)
    0x85, 0x82,        //   Report ID (-126)
    0x09, 0x06,        //   Usage (0x06)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x3F,        //   Report Count (63)
    0x91, 0x83,        //   Output (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Volatile)
    0xC0
};

/* https://mzyy94.com/blog/2020/03/20/nintendo-switch-pro-controller-usb-gadget/ */
/*
typedef struct {
    bool button_1:1;
    bool button_2:1;
    bool button_3:1;
    bool button_4:1;
    bool button_5:1;
    bool button_6:1;
    bool button_7:1;
    bool button_8:1;
    bool button_9:1;
    bool button_10:1;
    bool button_11:1;
    bool button_12:1;
    bool button_13:1;
    bool button_14:1;
    int16_t x;
    int16_t y;
    int16_t z;
    int16_t rz;
    uint8_t dpad:4;
    bool button_15: 1;
    bool button_16: 1;
    bool button_17: 1;
    bool button_18: 1;
} USB_HID_Report_t;
*/

#endif // FIRMWARE_DATATYPES_H
