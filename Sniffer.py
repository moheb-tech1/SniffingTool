import socket
import struct
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from time import sleep
from rich.progress import track
from rich.box import *
from rich.align import Align
from pyfiglet import figlet_format as ff

try:
    logo = ff("Socket Sniffer")
    for i in logo :
        Console().print(f"[bold purple]{i}", end="")
        sleep(0.005)

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP )

    Console().print(Align.left(Panel("[bold cyan]Packet Sniffer Started!...")))
    table = Table(title="Details", style="blue", box=ASCII_DOUBLE_HEAD)
    table.add_column("IP(src)", style="green")
    table.add_column("IP(dst)", style="yellow")
    table.add_column("Protocol", style="purple")
    table.add_column("Length", style="cyan")
    while True:
        packet, addr = sniffer.recvfrom(65535)

        ip_header = packet[:20]

        version_ihl, tos, total_length, identification, flags_offset, ttl, protocol, checksum, src,dst = struct.unpack("!BBHHHBBH4s4s", ip_header)

        src_ip = socket.inet_ntoa(src)
        dst_ip = socket.inet_ntoa(dst)

        if protocol == 1:
            proto = "ICMP"
        elif protocol == 6:
            proto = "TCP"
        elif protocol == 17:
            proto = "UDP"
        else:
            proto = f"Unknown ({protocol})"
        table.add_row(str(src_ip), str(dst_ip), str(proto), f"{str(total_length)} Bytes")
        Console().print(table)
        Console().print("[bold blue]Updating...(1)s")
        sleep(1)
        
except Exception as e:
    print(f"\033[1;31mError: {e}")
except KeyboardInterrupt:
    exit(1)