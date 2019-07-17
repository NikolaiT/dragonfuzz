import struct

ETH_P_ALL = 3

def mac2str(mac):
    return bytes.fromhex(mac.replace(':', ' '))


def get_sae_frame(sta_mac, ap_mac, sequence=b"\x01\x00", status=b"\x00\x00", offset=''):
    """
    Setup a SAE frame

    :param sta_mac: MAC address of the station. This is the fuzzing client
    :param ap_mac: MAC address of the authenticator that is fuzzed
    :param sequence: sequence number in mgmt auth body
    :param status: status number in mgmt auth body
    :param offset: offset to various parts of the SAE frame

    :return: the setup frame
    """
    frame = bytearray(AUTH_REQ_SAE)

    # add mac addresses
    sta_mac_bytes = mac2str(sta_mac)
    ap_mac_bytes = mac2str(ap_mac)

    frame[4:10] = ap_mac_bytes
    frame[10:16] = sta_mac_bytes
    frame[16:22] = ap_mac_bytes

    frame[26:28] = sequence
    frame[28:30] = status

    if offset == 'sae_body':
        frame = frame[:-98]
    elif offset == 'mgmt_body':
        frame = frame[:-104]

    frame = DEFAULT_RADIOTAP_HEADER + frame

    return frame


def get_deauth_frame(sta_mac, ap_mac):
    frame = DEAUTH

    # add mac addresses
    sta_mac_bytes = mac2str(sta_mac)
    ap_mac_bytes = mac2str(ap_mac)

    frame[4:10] = ap_mac_bytes
    frame[10:16] = sta_mac_bytes
    frame[16:22] = ap_mac_bytes

    return frame


# 802.11 radiotap header
# Check here: https://www.radiotap.org/
RADIOTAP_HEADER =              b"\x00" # header revision / version
RADIOTAP_HEADER             += b"\x00" # header pad, unused
RADIOTAP_HEADER             += b"\x1a\x00" # header length
RADIOTAP_HEADER             += b"\x2f\x48\x00\x00" # present flags
RADIOTAP_HEADER             += b"\x00\x00\x00\x00\x00\x00\x00\x00" # MAC timestamp
RADIOTAP_HEADER             += b"\x00" # flags
RADIOTAP_HEADER             += b"\x02" # data rate:
RADIOTAP_HEADER             += b"\x6c\x09" # channel frequency
RADIOTAP_HEADER             += b"\xa0\x00" # channel flags
RADIOTAP_HEADER             += b"\xe2" # SSI signal
RADIOTAP_HEADER             += b"\x00" # antenna
RADIOTAP_HEADER             += b"\x00\x00" # RX flags

# no flags present, let the 802.11 driver add the stuff
DEFAULT_RADIOTAP_HEADER = b'\x00\x00\x08\x00\x00\x00\x00\x00'


AUTH_REQ_OPEN       = b"\xB0"            # Type/Subtype
AUTH_REQ_OPEN      += b"\x00"            # Flags
AUTH_REQ_OPEN      += b"\x3A\x01"        # Duration ID
AUTH_REQ_OPEN      += b"\x00\x00\x00\x00\x00\x00"   # Destination address
AUTH_REQ_OPEN      += b"\x00\x00\x00\x00\x00\x00"  # Source address
AUTH_REQ_OPEN      += b"\x00\x00\x00\x00\x00\x00"   # BSSID
AUTH_REQ_OPEN      += b"\x01\x00"        # Sequence control
AUTH_REQ_OPEN      += b"\x00\x00"        # Authentication algorithm (open)
AUTH_REQ_OPEN      += b"\x01\x00"        # Authentication sequence number
AUTH_REQ_OPEN      += b"\x00\x00"        # Authentication status
AUTH_REQ_HDR        = AUTH_REQ_OPEN[:-6]


SAE_SCALAR = b"\xFA\x58\xEE\x8C\xB7\x00\x31\xA2\x79\xBD\x3A\xA5\x02\xDD\x5C\x5E\xE3\xEB\xDA\x05\x46\x59\xF6\x19\xFF\x0D\x97\x4A\xC6\x03\xFC\x11"
SAE_X = b"\x9E\xF3\x26\x31\x73\xFB\xDF\x60\x01\xB1\x75\xE7\x88\x32\x1E\x2C\x64\x22\x91\x20\xEA\x16\x05\x30\x94\xDB\x41\xB5\xF1\xA5\x8D\x22"
SAE_Y = b"\x5E\x25\x31\x49\x18\x71\xD3\x17\x89\x98\x3F\x29\x7E\x56\x35\x1F\x42\x58\x5F\x8E\x34\x1C\xB3\xFE\x17\x71\x29\x4B\x20\xAD\x32\xEB"

AUTH_REQ_SAE      = b"\xB0"            # Type/Subtype
AUTH_REQ_SAE      += b"\x00"            # Flags
AUTH_REQ_SAE      += b"\x00\x00"        # Duration ID
AUTH_REQ_SAE      += b"\x00\x00\x00\x00\x00\x00"   # Destination address
AUTH_REQ_SAE      += b"\x00\x00\x00\x00\x00\x00"  # Source address
AUTH_REQ_SAE      += b"\x00\x00\x00\x00\x00\x00"   # BSSID
AUTH_REQ_SAE      += b"\x10\x00"        # Sequence control, last 4 bits are fragment number, first 16 bits are sequence number

AUTH_REQ_SAE      += b"\x03\x00"        # Authentication algorithm (SAE)
AUTH_REQ_SAE      += b"\x01\x00"        # Authentication sequence number
AUTH_REQ_SAE      += b"\x00\x00"        # Authentication status
AUTH_REQ_SAE      += b"\x13\x00"        # Group Id = 19
AUTH_REQ_SAE      += SAE_SCALAR   # Scalar
AUTH_REQ_SAE      += SAE_X        # X-Coordinate ECC
AUTH_REQ_SAE      += SAE_Y        # Y-Coordinate ECC

AUTH_REQ_HDR_SAE = AUTH_REQ_SAE[:-98]

# pointer to the beginning of the mgmt authentication body
AUTH_REQ_BODY_MGMT = AUTH_REQ_SAE[:-104]

DEAUTH              = b"\xC0"            # Type/Subtype
DEAUTH             += b"\x00"            # Flags
DEAUTH             += b"\x3A\x01"        # Duration ID
DEAUTH             += b"\x00\x00\x00\x00\x00\x00"   # Destination address
DEAUTH             += b"\x00\x00\x00\x00\x00\x00"  # Source address
DEAUTH             += b"\x00\x00\x00\x00\x00\x00"   # BSSID
DEAUTH             += b"\x00\x00"        # Sequence control
DEAUTH             += b"\x02\x00"        # Reason code

