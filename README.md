# Dragonfuzz

Fuzz the WPA3 SAE authentication. We will fuzz the Auth-Commit frame and the Auth-Confirm frame.

As fuzzing library we are going to use boofuzz.

The testing infrastructure is created via hardware simulation of WiFi radios

```bash
# kill all interfering daemons such as network-manager
sudo pkill wpa_supplicant
sudo service network-manager stop

# create 3 virtual 802.11 radios named wlan0, wlan1, wlan2
sudo modprobe mac80211_hwsim radios=3
rfkill unblock wifi
```

Monitor radio simulation traffic in wireshark with:

```bash
sudo ifconfig hwsim0 up
```

## Before Fuzzing

Sources:
1. [How to use raw sockets in 802.11](https://stackoverflow.com/questions/48271119/how-to-send-both-802-11-management-frames-and-data-frames-using-raw-sockets-in-l)
2. [Injection Test](https://www.aircrack-ng.org/doku.php?id=injection_test)

In order to send management, data or any type of pure raw packet from a wireless interface you have to do the following:

1. Make sure the wireless interface hardware supports packet injection in monitor mode.
    + To check the capabilities of your WiFi card, you can check the following command: `iw list | grep -A7 "interface modes:"` If it outputs **monitor**, you are good to go.
    + To confirm injection tests, you can use `aireplay-ng -9 -e teddy -a 00:de:ad:ca:fe:00 -i {AP interface} {STA interface}`

2. Set the wireless interface in monitor mode. e.g.
    ```bash
    # the first commands kill interfering processes
    airmon-ng check kill
    service network-manager stop
    pkill wpa_supplicant
    # this puts the card in monitor mode
    ifconfig {dev} down
    iwconfig {dev} mode monitor
    ifconfig {dev} up
    # this sets the appropriate channel
    iwconfig {dev} channel {channel}
    ```

3. Create a raw socket via 
    ```python
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((dev, ETH_P_ALL))
    ```

4. Finally, Build and append at the beginning, the appropriate radiotap header while building your wireless 802.11 packet for management and control frames. Since you are basically bypassing all lower lever wireless drivers (which handles management and control frames), it becomes your job to include the radiotap header. [Info about radiotap header.](https://www.radiotap.org/)
    

### Radiotap Header

The radiotap header format is a mechanism to supply additional information about frames, from the driver to userspace applications such as libpcap, and from a userspace application to the driver for transmission. Designed initially for NetBSD systems by David Young, the radiotap header format provides more flexibility than the Prism or AVS header formats and allows the driver developer to specify an arbitrary number of fields based on a bitmask presence field in the radiotap header.


## Installation

We will use `pipenv` as package manager.



Install boofuzz directly from repo:

```bash

pipenv install git+https://github.com/jtpereyda/boofuzz#egg=boofuzz

```