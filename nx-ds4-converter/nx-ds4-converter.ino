#include <pico/cyw43_arch.h>
#include <class/hid/hid_device.h>
#include "cyw43.h"
#include "hci_dump.h"
#include "hci_dump_embedded_stdout.h"
#include "datatypes.h"
#include "Adafruit_TinyUSB.h"
#define HID_REPORT_TYPE_INPUT HID_REPORT_TYPE_INPUT_BT
#define HID_REPORT_TYPE_OUTPUT HID_REPORT_TYPE_OUTPUT_BT
#define HID_REPORT_TYPE_FEATURE HID_REPORT_TYPE_FEATURE_BT
#define hid_report_type_t hid_report_type_t_bt
#include <btstack.h>
#include <btstack_hid.h>
#undef hid_report_type_t
#undef HID_REPORT_TYPE_FEATURE
#undef HID_REPORT_TYPE_OUTPUT
#undef HID_REPORT_TYPE_INPUT

//User Config
//Please enter your dualshock4 mac address
static const char * remote_addr_string = "FF:FF:FF:FF:FF:FF";
//Mac address used by the USB device(little endian)
uint8_t mac_address[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
//Controller color hex code
uint8_t controller_color[] = {0xFF, 0xFF, 0xFF};
uint8_t button_color[] = {0x00, 0x00, 0x00};
uint8_t left_grip_color[] = {0xa9, 0xa9, 0xa9};
uint8_t right_grip_color[] = {0xa9, 0xa9, 0xa9};
//Gyro Sensitivity
#define GXSENS 1.2
#define GYSENS 1.2
#define GZSENS 1.2
//Rapid-fire function
#define EN_RF 1

#define MAX_ATTRIBUTE_VALUE_SIZE 500
static bd_addr_t remote_addr;
static btstack_packet_callback_registration_t hci_event_callback_registration;
static uint8_t hid_descriptor_storage[MAX_ATTRIBUTE_VALUE_SIZE];
#define COUNTER_INCREMENT 1
static bool startReport = false;
static bool imu_enable = false;
uint8_t replyBuffer[64];
static uint8_t counter = 0;
static bool nextPacketReady = false;
USB_ExtendedReport_t copy1;
Adafruit_USBD_HID usb_hid(hid_report_descriptor, sizeof(hid_report_descriptor), HID_ITF_PROTOCOL_NONE, 8, true);
static uint8_t out = 0xA;
static uint16_t hid_host_cid = 0;
static bool     hid_host_descriptor_available = false;
static hid_protocol_mode_t hid_host_report_mode = HID_PROTOCOL_MODE_REPORT;
static bool mashcount = false;

static void hid_host_handle_dualshock4(const uint8_t * report, uint16_t report_len){
    if (report_len < 28) return;
    if (report[0] != 0xa1) return;
    copy1.standardReport.button_x = report[8] & 0x80 ? 1 : 0;
    copy1.standardReport.button_a = report[8] & 0x40 ? 1 : 0;
    copy1.standardReport.button_b = report[8] & 0x20 ? 1 : 0;
    copy1.standardReport.button_y = report[8] & 0x10 ? 1 : 0;
    copy1.standardReport.dpad_up = 0;
    copy1.standardReport.dpad_down = 0;
    copy1.standardReport.dpad_right = 0;
    copy1.standardReport.dpad_left = 0;
    switch(report[8] & 0x0F){
        case HAT_TOP:
            copy1.standardReport.dpad_up = 1;
            break;
        case HAT_TOP_LEFT:
            copy1.standardReport.dpad_up = 1;
            copy1.standardReport.dpad_left = 1;
            break;
        case HAT_TOP_RIGHT:
            copy1.standardReport.dpad_up = 1;
            copy1.standardReport.dpad_right = 1;
            break;
        case HAT_RIGHT:
            copy1.standardReport.dpad_right = 1;
            break;
        case HAT_LEFT:
            copy1.standardReport.dpad_left = 1;
            break;
        case HAT_BOTTOM:
            copy1.standardReport.dpad_down = 1;
            break;
        case HAT_BOTTOM_LEFT:
            copy1.standardReport.dpad_down = 1;
            copy1.standardReport.dpad_left = 1;
            break;
        case HAT_BOTTOM_RIGHT:
            copy1.standardReport.dpad_down = 1;
            copy1.standardReport.dpad_right = 1;
            break;
        case HAT_CENTER:
        default:
            break;
    }
    copy1.standardReport.button_thumb_r = report[9] & 0x80 ? 1 : 0;
#if EN_RF
    copy1.standardReport.button_thumb_l = copy1.standardReport.button_l = report[9] & 0x40 ? 1 : 0;
    if (report[9] & 0x08 && report[9] & 1) {
        mashcount = true;
    } else {
        mashcount = false;
    }
#else
    copy1.standardReport.button_thumb_l = report[9] & 0x40 ? 1 : 0;
    copy1.standardReport.button_l = report[9] & 0x01 ? 1 : 0;
#endif
    copy1.standardReport.button_plus = report[9] & 0x20 ? 1 : 0;
    copy1.standardReport.button_minus = report[9] & 0x10 ? 1 : 0;
    copy1.standardReport.button_zr = report[9] & 0x08 ? 1 : 0;
    copy1.standardReport.button_zl = report[9] & 0x04 ? 1 : 0;
    copy1.standardReport.button_r = report[9] & 0x02 ? 1 : 0;
    copy1.standardReport.button_capture = report[10] & 0x02 ? 1 : 0;
    copy1.standardReport.button_home = report[10] & 0x01 ? 1 : 0;
    uint16_t lx = report[4] << 4;
    uint16_t ly;
    uint16_t rx = report[6] << 4;
    uint16_t ry;
    if (report[5] > 0x80) {
        ly = 0x80 - (report[5] - 0x80);
    } else if (report[5] < 0x80) {
        ly = 0x80 + -(report[5] - 0x80);
        if (ly > 255) {
            ly = 255;
        }
    } else {
        ly = 0x80;
    }
    ly <<= 4;
    if (report[7] > 0x80) {
        ry = 0x80 - (report[7] - 0x80);
    } else if (report[7] < 0x80) {
        ry = 0x80 + -(report[7] - 0x80);
        if (ry > 255) {
            ry = 255;
        }
    } else {
        ry = 0x80;
    }
    ry <<= 4;
    copy1.standardReport.analog[0] = lx & 0xFF;
    copy1.standardReport.analog[1] = ((ly & 0x0F) << 4) | ((lx & 0xF00) >> 8);
    copy1.standardReport.analog[2] = (ly & 0xFF0) >> 4;
    copy1.standardReport.analog[3] = rx & 0xFF;
    copy1.standardReport.analog[4] = ((ry & 0x0F) << 4) | ((rx & 0xF00) >> 8);
    copy1.standardReport.analog[5] = (ry & 0xFF0) >> 4;

    if (out == 0xA) {
        out = 0xC;
    } else if (out == 0xC) {
        out = 0xB;
    } else if (out == 0xB) {
        out = 0x9;
    } else {
        out = 0xA;
    }
    copy1.standardReport.vibrator_input_report = out;

    copy1.imu[12] = copy1.imu[6] = copy1.imu[0] = -((int16_t)((report[27] << 8) | (report[26] & 0xFF))) / 2; //acz

    copy1.imu[13] = copy1.imu[7] = copy1.imu[1] = -((int16_t)((report[23] << 8) | (report[22] & 0xFF))) / 2; //acx

    int16_t acy = ((int16_t)((report[25] << 8) | (report[24] & 0xFF))) / 2;
    if (acy > 0) {
        copy1.imu[14] = copy1.imu[8] = copy1.imu[2] = (((int16_t)((report[25] << 8) | (report[24] & 0xFF))) / 2) - 1000;
    } else if (acy == 0) {
        copy1.imu[14] = copy1.imu[8] = copy1.imu[2] = 0;
    } else {
        copy1.imu[14] = copy1.imu[8] = copy1.imu[2] = (((int16_t)((report[25] << 8) | (report[24] & 0xFF))) / 2) + 1000;
    }

    copy1.imu[15] = copy1.imu[9] = copy1.imu[3] = -((int16_t)((report[21] << 8) | (report[20] & 0xFF))) * GZSENS; //gz

    copy1.imu[16] = copy1.imu[10] = copy1.imu[4] = -((int16_t)((report[17] << 8) | (report[16] & 0xFF))) * GXSENS; //gx

    copy1.imu[17] = copy1.imu[11] = copy1.imu[5] = ((int16_t)((report[19] << 8) | (report[18] & 0xFF))) * GYSENS; //gy
}

static void packet_handler (uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
    /* LISTING_PAUSE */
    UNUSED(channel);
    UNUSED(size);

    uint8_t   event;
    bd_addr_t event_addr;
    uint8_t   status;

    /* LISTING_RESUME */
    switch (packet_type) {
		case HCI_EVENT_PACKET:
            event = hci_event_packet_get_type(packet);
            
            switch (event) {            
#ifndef HAVE_BTSTACK_STDIN
                /* @text When BTSTACK_EVENT_STATE with state HCI_STATE_WORKING
                 * is received and the example is started in client mode, the remote SDP HID query is started.
                 */
                case BTSTACK_EVENT_STATE:
                    if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING){
                        status = hid_host_connect(remote_addr, hid_host_report_mode, &hid_host_cid);
                        if (status != ERROR_CODE_SUCCESS){
                            //printf("HID host connect failed, status 0x%02x.\n", status);
                        }
                    }
                    break;
#endif
                /* LISTING_PAUSE */
                case HCI_EVENT_PIN_CODE_REQUEST:
					// inform about pin code request
                    //printf("Pin code request - using '0000'\n");
                    hci_event_pin_code_request_get_bd_addr(packet, event_addr);
                    gap_pin_code_response(event_addr, "0000");
					break;

                case HCI_EVENT_USER_CONFIRMATION_REQUEST:
                    // inform about user confirmation request
                    //printf("SSP User Confirmation Request with numeric value '%" PRIu32 "'\n", little_endian_read_32(packet, 8));
                    //printf("SSP User Confirmation Auto accept\n");
                    break;

                /* LISTING_RESUME */
                case HCI_EVENT_HID_META:
                    switch (hci_event_hid_meta_get_subevent_code(packet)){

                        case HID_SUBEVENT_INCOMING_CONNECTION:
                            // There is an incoming connection: we can accept it or decline it.
                            // The hid_host_report_mode in the hid_host_accept_connection function 
                            // allows the application to request a protocol mode. 
                            // For available protocol modes, see hid_protocol_mode_t in btstack_hid.h file. 
                            hid_host_accept_connection(hid_subevent_incoming_connection_get_hid_cid(packet), hid_host_report_mode);
                            break;
                        
                        case HID_SUBEVENT_CONNECTION_OPENED:
                            // The status field of this event indicates if the control and interrupt
                            // connections were opened successfully.
                            status = hid_subevent_connection_opened_get_status(packet);
                            if (status != ERROR_CODE_SUCCESS) {
                                //printf("Connection failed, status 0x%x\n", status);
                                //app_state = APP_IDLE;
                                hid_host_cid = 0;
                                return;
                            }
                            //app_state = APP_CONNECTED;
                            hid_host_descriptor_available = false;
                            hid_host_cid = hid_subevent_connection_opened_get_hid_cid(packet);
#if EN_A
                            asend = true;
#endif
                            //printf("HID Host connected.\n");
                            //hid_host_send_get_report(hid_host_cid, HID_REPORT_TYPE_FEATURE_BT, 0x05);
                            break;

                        case HID_SUBEVENT_DESCRIPTOR_AVAILABLE:
                            // This event will follows HID_SUBEVENT_CONNECTION_OPENED event. 
                            // For incoming connections, i.e. HID Device initiating the connection,
                            // the HID_SUBEVENT_DESCRIPTOR_AVAILABLE is delayed, and some HID  
                            // reports may be received via HID_SUBEVENT_REPORT event. It is up to 
                            // the application if these reports should be buffered or ignored until 
                            // the HID descriptor is available.
                            status = hid_subevent_descriptor_available_get_status(packet);
                            if (status == ERROR_CODE_SUCCESS){
                                hid_host_descriptor_available = true;
                                //printf("HID Descriptor available, please start typing.\n");
                                hid_host_send_get_report(hid_host_cid, HID_REPORT_TYPE_FEATURE_BT, 0x05);
                            } else {
                                //printf("Cannot handle input report, HID Descriptor is not available.\n");
                            }
                            break;

                        case HID_SUBEVENT_REPORT:
                            // Handle input report.
                            //if (hid_host_descriptor_available){
                            //    hid_host_handle_interrupt_report(hid_subevent_report_get_report(packet), hid_subevent_report_get_report_len(packet));
                            //} else {
                                //printf_hexdump(hid_subevent_report_get_report(packet), hid_subevent_report_get_report_len(packet));
                                //if (!asend) asend = true;
                                hid_host_handle_dualshock4(hid_subevent_report_get_report(packet), hid_subevent_report_get_report_len(packet));
                                //memcpy(lastdsreport, hid_subevent_report_get_report(packet), hid_subevent_report_get_report_len(packet));
                            //}
                            break;

                        case HID_SUBEVENT_SET_PROTOCOL_RESPONSE:
                            // For incoming connections, the library will set the protocol mode of the
                            // HID Device as requested in the call to hid_host_accept_connection. The event 
                            // reports the result. For connections initiated by calling hid_host_connect, 
                            // this event will occur only if the established report mode is boot mode.
                            status = hid_subevent_set_protocol_response_get_handshake_status(packet);
                            if (status != HID_HANDSHAKE_PARAM_TYPE_SUCCESSFUL){
                                //printf("Error set protocol, status 0x%02x\n", status);
                                break;
                            }
                            switch ((hid_protocol_mode_t)hid_subevent_set_protocol_response_get_protocol_mode(packet)){
                                case HID_PROTOCOL_MODE_BOOT:
                                    //printf("Protocol mode set: BOOT.\n");
                                    break;  
                                case HID_PROTOCOL_MODE_REPORT:
                                    //printf("Protocol mode set: REPORT.\n");
                                    break;
                                default:
                                    //printf("Unknown protocol mode.\n");
                                    break; 
                            }
                            break;

                        //case HID_SUBEVENT_CAN_SEND_NOW:
                        //    if (!asend) asend = true;
                        //    break;
                        case HID_SUBEVENT_CONNECTION_CLOSED:
                            // The connection was closed.
                            hid_host_cid = 0;
                            hid_host_descriptor_available = false;
                            //printf("HID Host disconnected.\n");
                            break;
                        
                        default:
                            break;
                    }
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
}

void setup() {
    l2cap_init();
    hid_host_init(hid_descriptor_storage, sizeof(hid_descriptor_storage));
    hid_host_register_packet_handler(packet_handler);
    gap_set_default_link_policy_settings(LM_LINK_POLICY_ENABLE_SNIFF_MODE | LM_LINK_POLICY_ENABLE_ROLE_SWITCH);
    hci_set_master_slave_policy(HCI_ROLE_MASTER);
    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);
    sscanf_bd_addr(remote_addr_string, remote_addr);
    hci_power_control(HCI_POWER_ON);
}

void loop() {
    absolute_time_t t_ti2 = make_timeout_time_us(5000);
    counter += COUNTER_INCREMENT;
    hid_host_send_get_report(hid_host_cid, HID_REPORT_TYPE_FEATURE_BT, 0x05);
    while (!time_reached(t_ti2)) {}
}

static void prepare_reply(uint8_t code, uint8_t command, uint8_t data[], uint8_t length) {
    if (nextPacketReady) return;
    memset(replyBuffer, 0, sizeof(replyBuffer));
    replyBuffer[0] = code;
    replyBuffer[1] = command;
    memcpy(&replyBuffer[2], &data[0], length);
    nextPacketReady = true;
}

static void prepare_uart_reply(uint8_t code, uint8_t subcommand, uint8_t data[], uint8_t length) {
    if (nextPacketReady) return;
    memset(replyBuffer, 0, sizeof(replyBuffer));
    replyBuffer[0] = 0x21;
    replyBuffer[1] = counter;
    size_t n = sizeof(USB_StandardReport_t);
    memcpy(&replyBuffer[2], &(copy1.standardReport), n);
    replyBuffer[n + 2] = code;
    replyBuffer[n + 3] = subcommand;
    memcpy(&replyBuffer[n + 4], &data[0], length);
    nextPacketReady = true;
}

static size_t min_size(size_t s1, size_t s2) {
    return s1 > s2 ? s2 : s1;
}

/*
 * Read 'size' bytes starting with 'address' and save them in 'buf'.
 * See https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/master/spi_flash_notes.md
 */
void spi_read(SPI_Address_t address, size_t size, uint8_t buf[]) {
    memset(buf, 0xFF, size);
    switch (address) {
        default:
        case ADDRESS_SERIAL_NUMBER: {
            // All 0xFF, leave buf as it is
            break;
        }
        case ADDRESS_CONTROLLER_COLOR: {
            if (size >= 3) {
                memcpy(&buf[0], &controller_color[0], sizeof(controller_color));
            }
            if (size >= 6) {
                memcpy(&buf[3], &button_color[0], sizeof(button_color));
            }
            if (size >= 9) {
                memcpy(&buf[6], &left_grip_color[0], sizeof(left_grip_color));
            }
            if (size >= 12) {
                memcpy(&buf[9], &right_grip_color[0], sizeof(right_grip_color));
            }
            break;
        }
        case ADDRESS_FACTORY_PARAMETERS_1: {
            uint8_t factory_parameters_1[] = {0x50, 0xfd, 0x00, 0x00, 0xc6, 0x0f, 0x0f, 0x30, 0x61, 0x96, 0x30, 0xf3,
                                              0xd4, 0x14, 0x54, 0x41, 0x15, 0x54, 0xc7, 0x79, 0x9c, 0x33, 0x36, 0x63};
            memcpy(&buf[0], &factory_parameters_1[0], min_size(size, sizeof(factory_parameters_1)));
            break;
        }
        case ADDRESS_FACTORY_PARAMETERS_2: {
            uint8_t factory_parameters_2[] = {0x0f, 0x30, 0x61, 0x96, 0x30, 0xf3, 0xd4, 0x14, 0x54,
                                              0x41, 0x15, 0x54, 0xc7, 0x79, 0x9c, 0x33, 0x36, 0x63};
            memcpy(&buf[0], &factory_parameters_2[0], min_size(size, sizeof(factory_parameters_2)));
            break;
        }
        case ADDRESS_FACTORY_CALIBRATION_1: {
            uint8_t factory_calibration_1[] = {0xEE, 0xFC, 0xBD, 0xFF, 0xF6, 0x0F, 0x00, 0x40, 0x00, 0x40, 0x00, 0x40,
                                               0x05, 0x00, 0xF8, 0xFF, 0x04, 0x00, 0xE7, 0x3B, 0xE7, 0x3B, 0xE7, 0x3B};
            memcpy(&buf[0], &factory_calibration_1[0], min_size(size, sizeof(factory_calibration_1)));
            break;
        }
        case ADDRESS_FACTORY_CALIBRATION_2: {
            uint8_t factory_calibration_2[] = {0xba, 0x15, 0x62, 0x11, 0xb8, 0x7f, 0x29, 0x06, 0x5b, 0xff, 0xe7, 0x7e,
                                               0x0e, 0x36, 0x56, 0x9e, 0x85, 0x60, 0xff, 0x32, 0x32, 0x32, 0xff, 0xff,
                                               0xff};
            memcpy(&buf[0], &factory_calibration_2[0], min_size(size, sizeof(factory_calibration_2)));
            break;
        }
        case ADDRESS_STICKS_CALIBRATION: {
            if (size > 22) {
                buf[22] = 0xB2;
            }
            if (size > 23) {
                buf[23] = 0xA1;
            }
            // spi_response(data[11:13], bytes.fromhex('ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff b2 a1'))
            break;
        }
        case ADDRESS_IMU_CALIBRATION: {
            uint8_t imu_calibration[] = {0xbe, 0xff, 0x3e, 0x00, 0xf0, 0x01, 0x00, 0x40, 0x00, 0x40, 0x00, 0x40,
                                         0xfe, 0xff, 0xfe, 0xff, 0x08, 0x00, 0xe7, 0x3b, 0xe7, 0x3b, 0xe7, 0x3b};
            memcpy(&buf[0], &imu_calibration[0], min_size(size, sizeof(imu_calibration)));
            break;
        }
    }
}

static void prepare_spi_reply(SPI_Address_t address, size_t size) {
    uint8_t data[size];
    // Populate buffer with data read from SPI flash
    spi_read(address, size, data);

    uint8_t spiReplyBuffer[5 + size];
    // Big-endian
    spiReplyBuffer[0] = address & 0xFF;
    spiReplyBuffer[1] = (address >> 8) & 0xFF;
    spiReplyBuffer[2] = 0x00;
    spiReplyBuffer[3] = 0x00;
    spiReplyBuffer[4] = size;
    memcpy(&spiReplyBuffer[5], &data[0], size);

    prepare_uart_reply(0x90, SUBCOMMAND_SPI_FLASH_READ, spiReplyBuffer, sizeof(spiReplyBuffer));
}

static void prepare_standard_report(USB_StandardReport_t *standardReport) {
    if (nextPacketReady) return;
    prepare_reply(0x30, counter, (uint8_t *) standardReport, sizeof(USB_StandardReport_t));
}

static void prepare_extended_report(USB_ExtendedReport_t *extendedReport) {
    if (nextPacketReady) return;
    prepare_reply(0x30, counter, (uint8_t *) extendedReport, sizeof(USB_ExtendedReport_t));
}

static void prepare_8101(void) {
    if (nextPacketReady) return;
    size_t n = sizeof(mac_address); // = 6
    uint8_t buf[n + 2];
    buf[0] = 0x00;
    buf[1] = 0x03; // Pro Controller
    memcpy(&buf[2], &mac_address[0], n);
    prepare_reply(0x81, 0x01, buf, sizeof(buf));
}

void ep2_out_handler(uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize)
{
    if (buffer[0] == 0x80) {
        switch (buffer[1]) {
            case 0x01: {
                prepare_8101();
                break;
            }
            case 0x02:
            case 0x03: {
                prepare_reply(0x81, buffer[1], NULL, 0);
                break;
            }
            case 0x04: {
                startReport = true;
                prepare_standard_report(&(copy1.standardReport));
                break;
            }
            case 0x05: {
                startReport = false;
                break;
            }
            default: {
                // TODO
                prepare_reply(0x81, buffer[1], NULL, 0);
                break;
            }
        }
    } else if (buffer[0] == 0x01) {
        if (bufsize > 16) {
        Switch_Subcommand_t subcommand = (Switch_Subcommand_t)(buffer[10]);
        switch (subcommand) {
            case SUBCOMMAND_BLUETOOTH_MANUAL_PAIRING: {
                prepare_uart_reply(0x81, subcommand, (uint8_t *) 0x03, 1);
                break;
            }
            case SUBCOMMAND_REQUEST_DEVICE_INFO: {
                size_t n = sizeof(mac_address); // = 6
                uint8_t buf[n + 6];
                buf[0] = 0x03; buf[1] = 0x48; // Firmware version
                buf[2] = 0x03; // Pro Controller
                buf[3] = 0x02; // Unkown
                // MAC address is flipped (big-endian)
                for (unsigned int i = 0; i < n; i++) {
                    buf[(n + 3) - i] = mac_address[i];
                }
                buf[n + 4] = 0x03; // Unknown
                buf[n + 5] = 0x02; // Use colors in SPI memory, and use grip colors (added in Switch firmware 5.0)
                prepare_uart_reply(0x82, subcommand, buf, sizeof(buf));
                break;
            }
            case SUBCOMMAND_SET_INPUT_REPORT_MODE:
            case SUBCOMMAND_SET_SHIPMENT_LOW_POWER_STATE:
            case SUBCOMMAND_SET_PLAYER_LIGHTS:
            case SUBCOMMAND_SET_HOME_LIGHTS:
            case SUBCOMMAND_ENABLE_VIBRATION: {
                prepare_uart_reply(0x80, subcommand, NULL, 0);
                break;
            }
            case SUBCOMMAND_ENABLE_IMU: {
                if (buffer[11] == 0)
                {
                    imu_enable = false;
                }
                else
                {
                    imu_enable = true;
                }
                prepare_uart_reply(0x80, subcommand, NULL, 0);
                break;
            }
            case SUBCOMMAND_TRIGGER_BUTTONS_ELAPSED_TIME: {
                prepare_uart_reply(0x83, subcommand, NULL, 0);
                break;
            }
            case SUBCOMMAND_SET_NFC_IR_MCU_CONFIG: {
                uint8_t bufe[] = {0x01, 0x00, 0xFF, 0x00, 0x03, 0x00, 0x05, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5c};
                prepare_uart_reply(0xA0, subcommand, bufe, sizeof(bufe));
                break;
            }
            case SUBCOMMAND_SPI_FLASH_READ: {
                // SPI
                // Addresses are little-endian, so 80 60 means address 0x6080
                SPI_Address_t address = (SPI_Address_t)((buffer[12] << 8) | buffer[11]);
                size_t size = (size_t)buffer[15];
                prepare_spi_reply(address, size);
                break;
            }
            default: {
                // TODO
                prepare_uart_reply(0x80, subcommand, NULL, 0);
                break;
            }
        }
        }
    }
}

void setup1() {
    copy1.standardReport.connection_info = 1;
    copy1.standardReport.battery_level = BATTERY_FULL | BATTERY_CHARGING;
    copy1.standardReport.button_x = 0;
    copy1.standardReport.button_a = 0;
    copy1.standardReport.button_b = 0;
    copy1.standardReport.button_y = 0;
    copy1.standardReport.dpad_up = 0;
    copy1.standardReport.dpad_down = 0;
    copy1.standardReport.dpad_right = 0;
    copy1.standardReport.dpad_left = 0;
    copy1.standardReport.button_thumb_r = 0;
    copy1.standardReport.button_thumb_l = 0;
    copy1.standardReport.button_plus = 0;
    copy1.standardReport.button_minus = 0;
    copy1.standardReport.button_zr = 0;
    copy1.standardReport.button_zl = 0;
    copy1.standardReport.button_r = 0;
    copy1.standardReport.button_l = 0;
    copy1.standardReport.button_capture = 0;
    copy1.standardReport.button_home = 0;
    uint16_t lx = 0x0800;
    uint16_t ly = 0x0800;
    uint16_t rx = 0x0800;
    uint16_t ry = 0x0800;
    copy1.standardReport.analog[0] = lx & 0xFF;
    copy1.standardReport.analog[1] = ((ly & 0x0F) << 4) | ((lx & 0xF00) >> 8);
    copy1.standardReport.analog[2] = (ly & 0xFF0) >> 4;
    copy1.standardReport.analog[3] = rx & 0xFF;
    copy1.standardReport.analog[4] = ((ry & 0x0F) << 4) | ((rx & 0xF00) >> 8);
    copy1.standardReport.analog[5] = (ry & 0xFF0) >> 4;
#if defined(ARDUINO_ARCH_MBED) && defined(ARDUINO_ARCH_RP2040)
    // Manual begin() is required on core without built-in support for TinyUSB such as mbed rp2040
    TinyUSB_Device_Init(0);
#endif
    TinyUSBDevice.setID(0x057E,0x2009);
    TinyUSBDevice.setVersion(0x0200);
    TinyUSBDevice.setDeviceVersion(0x0200);
    TinyUSBDevice.setLanguageDescriptor(0x0409);
    TinyUSBDevice.setManufacturerDescriptor("Nintendo Co., Ltd.");
    TinyUSBDevice.setProductDescriptor("Pro Controller");
    TinyUSBDevice.setSerialDescriptor("000000000001");
    usb_hid.setReportCallback(NULL, ep2_out_handler);
    usb_hid.begin();
    while(!TinyUSBDevice.mounted()) delay(1);
}

#if EN_RF
static bool mash = false;
void mashA() {
    if (mashcount && !mash) {
        copy1.standardReport.button_zr = 0;
        mash = true;
    } else if (mash) {
        copy1.standardReport.button_zr = 1;
        mash = false;
    } else {
        mash = false;
    }
}
#endif

void loop1() {
#if EN_RF
    absolute_time_t t_ti = make_timeout_time_us(16666);
#else
    absolute_time_t t_ti = make_timeout_time_us(8000);
#endif
    if (!nextPacketReady) {
        // No requests from Switch, use standard report
        if (startReport)
        {
#if EN_RF
            mashA();
#endif
            if (imu_enable)
            {
                prepare_extended_report(&copy1);
            }
            else
            {
                prepare_standard_report(&(copy1.standardReport));
            }
        }
    }

    if (nextPacketReady)
    {
        usb_hid.sendReport(0, replyBuffer, sizeof(replyBuffer));
        nextPacketReady = false;
    }
    while (!time_reached(t_ti)) {}
}
