#!/usr/bin/env python

import logging
import socket
import time
import os
import argparse

# that is bad :(
from boofuzz import *
from scapy.all import *
from frames import *


logging.basicConfig(level=logging.DEBUG)


def monitor_mode(dev):
    """
    puts a card in monitor mode
    :param dev inteface to put in monitor mode
    :return:
    """
    if os.getuid() != 0:
        raise ValueError('need to be root. I am: {}'.format(os.getuid()))

    os.system('airmon-ng check kill')
    os.system('service network-manager stop')
    os.system('pkill wpa_supplicant')
    os.system(f'ifconfig {dev} down')
    os.system(f'iwconfig {dev} mode monitor')
    os.system(f'ifconfig {dev} up')


def set_channel(dev, channel=1):
    os.system(f'iwconfig {dev} channel {channel}')


def enable_hardware_sim():
    """
    setup hardware sim environment
    :return:
    """


def is_alive(dev):
    """
    confirm that the AP is alive by sending an AUTH frame and waiting for a
    successful response.

    :param dev:
    :return:
    """
    CRASH_RETRIES = 50
    ETH_P_ALL = 3

    def isresp(pkt):
        """
        Probe Request: wlan.fc.type_subtype == 0x0004
        Probe Response: wlan.fc.type_subtype == 0x0005
        Authentication frame: wlan.fc.type_subtype == 0x000b
        Association Request: wlan.fc.type_subtype == 0x0000
        Association Response: wlan.fc.type_subtype == 0x0001

        Beacon: wlan.fc.type_subtype == 0x0008

        :param pkt:
        :return:
        """
        header_length = struct.unpack('h', pkt[2:4])[0]

        hexdump(pkt)

        pkt = pkt[header_length:]

        resp = False
        if pkt[0:1] == b"\xb0":
            logging.info('received auth response')
        elif pkt[0:1] == b'\x40':
            logging.info('received probe request')
        elif pkt[0:1] == b'\x50':
            logging.info('received probe response')
        elif pkt[0:1] == b'\x00':
            logging.info('received assoc request')
        elif pkt[0:1] == b'\x00':
            logging.info('received assoc response')
        elif pkt[0:1] == b'\x80':
            logging.info('received beacon frame')

        if (len(pkt) >= 30 and pkt[0:1] == b"\xb0"
                and pkt[4:10] == frames.mac2str(AP_MAC)
                and pkt[28:30] == b"\x00\x00"):
            logging.info(f'received auth response from: {AP_MAC}')
            hexdump(pkt)
            resp = True
        return resp

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((dev, ETH_P_ALL))

    logging.info("checking aliveness of fuzzed access point {}".format(AP_MAC))

    retries = CRASH_RETRIES
    alive = False

    hexdump(AUTH_REQ_SAE)

    while retries:
        s.send(AUTH_REQ_SAE)
        logging.info('sent AUTH_REQ_SAE')

        start_time = time.time()
        while (time.time() - start_time) < 1:
            ans = s.recv(1024)
            alive = isresp(ans)
            if alive:
                s.send(DEAUTH)
                s.close()
                if retries != CRASH_RETRIES:
                    logging.info("retried authentication {} times".format(CRASH_RETRIES - retries))
                return alive

        retries -= 1

    s.close()

    return alive


def send_auth_scapy(iface, ap_mac, sta_mac):
    packet = Dot11(
        addr1=ap_mac,
        addr2=sta_mac,
        addr3=ap_mac) / Dot11Auth(
        algo=0x00, seqnum=0x0001, status=0x0000)
    packet.show()
    sendp(packet, iface=iface)
    packet.show()


def fuzz(args):
    connection = SocketConnection(
        host=args.iface,
        proto='raw-l2',
        ethernet_proto=socket.htons(ETH_P_ALL),
        send_timeout=5.0,
        recv_timeout=5.0
    )

    target = Target(connection=connection)

    session = Session(
        target=target
    )

    sae_body = get_sae_frame(args.sta_mac, args.ap_mac, offset='sae_body')
    mgmt_body = get_sae_frame(args.sta_mac, args.ap_mac, offset='mgmt_body')

    s_initialize('auth-commit fuzz invalid group')
    s_static(sae_body)
    s_word(0x0013,  fuzzable=True)
    s_static(SAE_SCALAR)
    s_static(SAE_X)
    s_static(SAE_Y)

    s_initialize('auth-commit fuzz status codes')
    s_static(mgmt_body)
    s_word(0x0003, fuzzable=False) # SAE auth algo
    s_word(0x0001, fuzzable=False) # sequence 1
    s_word(0x0, fuzzable=True) # MMPDU_STATUS_CODE_ANTI_CLOGGING_TOKEN_REQ = 76
    # now the body expects to have a anti-clogging token set
    s_random(b'', min_length=0, max_length=500, fuzzable=True)

    s_initialize('auth-commit fuzz anti clogging token')
    s_static(sae_body)
    s_word(0x0003, fuzzable=False) # SAE auth algo
    s_word(0x0001, fuzzable=False) # sequence 1
    s_word(76, fuzzable=False) # MMPDU_STATUS_CODE_ANTI_CLOGGING_TOKEN_REQ = 76
    # now the body expects to have a anti-clogging token set
    s_random(b'', min_length=0, max_length=100, fuzzable=True)

    req = s_get('auth-commit fuzz status codes')
    logging.info(f'Num mutations: {req.num_mutations()}')
    session.connect(req)
    session.fuzz()


def main():
    parser = argparse.ArgumentParser(
        usage='sudo python dragonfuzz.py --ap-mac 02:00:00:00:02:00 --sta-mac 02:00:00:00:01:00 --iface wlan2',
        description='AP fuzzer that fuzzes the Dragonfly handshake.',
        epilog='Dragonfuzz, (c) Nikolai Tschacher (Summer 2019)'
    )

    parser.add_argument('--sta-mac',  dest='sta_mac', help='STA MAC address (fuzzer)')
    parser.add_argument('--ap-mac', dest='ap_mac', help='AP MAC address (fuzzed)')
    parser.add_argument('--iface', dest='iface', default='wlan0', help='injection interface')
    parser.add_argument('--log_level', dest='log_level', type=int, default=3)
    parser.add_argument('-s', dest='setup', type=bool, default=False)

    args = parser.parse_args()

    if not args.sta_mac:
        parser.error('STA MAC address must be set')
    if not args.iface:
        parser.error('injection interface must be set')
    if not args.ap_mac:
        parser.error('AP MAC address must be set')

    logging.info(os.getuid())
    if args.setup:
        monitor_mode(args.iface)
        set_channel(args.iface, 1)

    fuzz(args)


if __name__ == '__main__':
    main()
