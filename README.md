# ESPTouch.py
Python Implementation of ESPTouch app for android
ESPTouch app is used to connect ESP8266 and ESP32 chips to internet (using a 2.45GHz Wifi)

User will have to import ESPTouch.py file and run ESPTouch(wifi_ssid, wifi_password) function for implementation of code

It has an inbuilt receiver which receives and parses data and gives MAC ID and IP address of the chip

There are 2 keyword arguments (kwargs) for the ESPTouch() function
1. number_of_devices_to_connect - determines number of devices you wish to connect (default = 1)
2. timeout - time for which code will wait for UDP packets (default = 60)

ESPTouch() function return list of MAC IDs of connected devices (else [-1])
e.g. for 2 devices -> ['aab67cdd23ff', 'acac56f432cd']
e.g. no device connected (no UDP packet received) -> [-1]

Data is transmitted for approx 48 secs (8 loops 6 secs each), this can be changed in sendData() function
