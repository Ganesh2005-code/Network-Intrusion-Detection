from collections import defaultdict
from datetime import datetime

from scapy.all import IP, TCP, UDP, ICMP


# ============================================================
# Flow storage
# ============================================================

flows = defaultdict(lambda: {
    "start_time": None,
    "last_time": None,

    "src_ip": None,
    "dst_ip": None,

    "protocol": None,
    "service": None,
    "flag": None,

    "src_bytes": 0,
    "dst_bytes": 0,

    "packet_count": 0,

    "syn_count": 0,
    "rst_count": 0,
    "fin_count": 0,

    "same_service_count": 0,
    "different_service_count": 0
})


# ============================================================
# Get protocol
# ============================================================

def get_protocol(packet):

    if TCP in packet:
        return "tcp"

    if UDP in packet:
        return "udp"

    if ICMP in packet:
        return "icmp"

    # NSL-KDD encoder does not contain "other"
    # Use icmp as the safest supported fallback.
    return "icmp"


# ============================================================
# Get service
# ============================================================

def get_service(packet):

    if TCP in packet:

        port = packet[TCP].dport

    elif UDP in packet:

        port = packet[UDP].dport

    else:

        return "other"


    # ========================================================
    # NSL-KDD service mapping
    # ========================================================

    service_map = {

        20: "ftp_data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "domain",
        80: "http",

        # HTTPS → NSL-KDD compatible category
        443: "http_443",

        110: "pop_3",
        111: "sunrpc",
        139: "netbios_ssn",
        143: "imap4",

        512: "exec",
        513: "login",
        514: "shell",

        # These are not NSL-KDD services,
        # so they fall back to "other".
        3306: "other",
        3389: "other"
    }


    return service_map.get(
        port,
        "other"
    )


# ============================================================
# Get TCP flag
# ============================================================

def get_flag(packet):

    if TCP not in packet:

        return "OTH"


    flags = str(packet[TCP].flags)


    # --------------------------------------------------------
    # SYN + ACK
    # NSL-KDD does not have "SA"
    # Use SF as supported fallback for established traffic.
    # --------------------------------------------------------

    if "S" in flags and "A" in flags:

        return "SF"


    # --------------------------------------------------------
    # SYN only
    # --------------------------------------------------------

    if "S" in flags and "A" not in flags:

        return "S0"


    # --------------------------------------------------------
    # FIN
    # --------------------------------------------------------

    if "F" in flags:

        return "SF"


    # --------------------------------------------------------
    # RESET
    # --------------------------------------------------------

    if "R" in flags:

        return "REJ"


    # --------------------------------------------------------
    # ACK
    # --------------------------------------------------------

    if "A" in flags:

        return "S1"


    return "OTH"


# ============================================================
# Process packet
# ============================================================

def process_packet(packet):

    if IP not in packet:

        return None


    # --------------------------------------------------------
    # Basic information
    # --------------------------------------------------------

    src_ip = packet[IP].src

    dst_ip = packet[IP].dst

    protocol = get_protocol(packet)

    service = get_service(packet)

    flag = get_flag(packet)

    timestamp = float(packet.time)

    packet_size = len(packet)


    # --------------------------------------------------------
    # Flow identifier
    # --------------------------------------------------------

    flow_key = (
        src_ip,
        dst_ip,
        protocol,
        service
    )


    # --------------------------------------------------------
    # Create flow
    # --------------------------------------------------------

    if flows[flow_key]["start_time"] is None:

        flows[flow_key]["start_time"] = timestamp

        flows[flow_key]["src_ip"] = src_ip

        flows[flow_key]["dst_ip"] = dst_ip

        flows[flow_key]["protocol"] = protocol

        flows[flow_key]["service"] = service

        flows[flow_key]["flag"] = flag


    flow = flows[flow_key]


    # --------------------------------------------------------
    # Update flow
    # --------------------------------------------------------

    flow["last_time"] = timestamp

    flow["packet_count"] += 1


    # --------------------------------------------------------
    # Bytes
    # --------------------------------------------------------

    if src_ip == flow["src_ip"]:

        flow["src_bytes"] += packet_size

    else:

        flow["dst_bytes"] += packet_size


    # --------------------------------------------------------
    # TCP information
    # --------------------------------------------------------

    if TCP in packet:

        flags = str(packet[TCP].flags)


        if "S" in flags:

            flow["syn_count"] += 1


        if "R" in flags:

            flow["rst_count"] += 1


        if "F" in flags:

            flow["fin_count"] += 1


    # --------------------------------------------------------
    # Return packet information
    # --------------------------------------------------------

    return {

        "source_ip": src_ip,

        "destination_ip": dst_ip,

        "protocol": protocol,

        "service": service,

        "flag": flag,

        "packet_size": packet_size,

        "time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    }


# ============================================================
# Convert flow to NSL-KDD style features
# ============================================================

def build_features(flow):

    # --------------------------------------------------------
    # Duration
    # --------------------------------------------------------

    if flow["start_time"] is None:

        duration = 0

    else:

        duration = (
            flow["last_time"]
            - flow["start_time"]
        )


    packet_count = flow["packet_count"]


    # --------------------------------------------------------
    # Error rate
    # --------------------------------------------------------

    if packet_count > 0:

        serror_rate = (
            flow["rst_count"]
            / packet_count
        )

    else:

        serror_rate = 0


    # ========================================================
    # Feature dictionary
    # ========================================================

    features = {

        "duration": duration,

        "protocol_type": flow["protocol"],

        "service": flow["service"],

        "flag": flow["flag"],

        "src_bytes": flow["src_bytes"],

        "dst_bytes": flow["dst_bytes"],

        "land": int(
            flow["src_ip"]
            == flow["dst_ip"]
        ),

        "wrong_fragment": 0,

        "urgent": 0,

        "hot": 0,

        "num_failed_logins": 0,

        "logged_in": 0,

        "num_compromised": 0,

        "root_shell": 0,

        "su_attempted": 0,

        "num_root": 0,

        "num_file_creations": 0,

        "num_shells": 0,

        "num_access_files": 0,

        "num_outbound_cmds": 0,

        "is_host_login": 0,

        "is_guest_login": 0,

        "count": packet_count,

        "srv_count": packet_count,

        "serror_rate": serror_rate,

        "srv_serror_rate": serror_rate,

        "rerror_rate": 0,

        "srv_rerror_rate": 0,

        "same_srv_rate": 1.0,

        "diff_srv_rate": 0.0,

        "srv_diff_host_rate": 0.0,

        "dst_host_count": packet_count,

        "dst_host_srv_count": packet_count,

        "dst_host_same_srv_rate": 1.0,

        "dst_host_diff_srv_rate": 0.0,

        "dst_host_same_src_port_rate": 1.0,

        "dst_host_srv_diff_host_rate": 0.0,

        "dst_host_serror_rate": serror_rate,

        "dst_host_srv_serror_rate": serror_rate,

        "dst_host_rerror_rate": 0.0,

        "dst_host_srv_rerror_rate": 0.0

    }


    return features