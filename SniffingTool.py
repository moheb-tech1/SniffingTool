import argparse as arg
from rich.table import Table as tab
from rich.progress import track as trc
from time import sleep as sp
from rich.console import Console as csl
import pyshark as ps
from pyfiglet import figlet_format as ff
from rich.box import *
from rich.panel import Panel

parser = arg.ArgumentParser(description="\033[35mSniffing Tool\033[34m", usage="\033[1;37mCommand[OPTION]")

parser.add_argument("-i", action="store_true" ,help="\033[34mShows the IP(src) and IP(dst).")
parser.add_argument("-l", action="store_true" ,help="\033[34mShows the packet length")
parser.add_argument("-s", action="store_true" ,help="\033[34mShows the name of sites")
parser.add_argument("-t", action="store_true" ,help="\033[34mShows the Transport Layers")
parser.add_argument("-hi",  action="store_true"  ,help="\033[34mShows the Highest Layers")
parser.add_argument("-a", action="store_true" ,help="\033[34mShows the All Details")
args = parser.parse_args()


def ip():
    try:
        logo = ff("IP")
        for i in logo:
            csl().print(i, style="purple", end="")
            sp(0.03)
        for i in "\n************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)
        
        interfaces = ps.LiveCapture().interfaces
        intt = []
        for i , n in enumerate(interfaces):
            intt.append(f"{i+1}. {n}")
        csl().print(Panel(str(intt) ,title="Interfaces",  style="green"))
        for i in "************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)

        interface = input("\033[44mEnter your interface name: \033[0m").strip()
        for i in trc(range(100), style="blue", description="\033[5;31mLoading...\033[0m"):
            sp(0.03)
        cap = ps.LiveCapture(interface=interface, bpf_filter="ip")
        count = int(input("\033[44mHow many packets do you want to receive: \033[0m").strip())
        for i in trc(range(100), style="blue", description="\033[5;31mWorking...\033[0m"):
            sp(0.03)
        table = tab(title="IP", style="blue", box=ASCII2)
        table.add_column("IP(src)", style="white")
        table.add_column("IP(dst)", style="green")
        
        try: 
            for i in cap.sniff_continuously(packet_count=count):
                
                
                src_ip = i.ip.src
                dst_ip = i.ip.dst
                table.add_row(src_ip, dst_ip)
            csl().print(table)
            
        except Exception as e:
            csl().print(Panel(str(e), title="Error", style="red"))
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))

            
def Dns():
    try:
        logo = ff("Length")
        for i in logo:
            csl().print(i, style="purple", end="")
            sp(0.03)
        for i in "\n************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)
        
        interfaces = ps.LiveCapture().interfaces
        intt = []
        for i , n in enumerate(interfaces):
            intt.append(f"{i+1}. {n}")
        csl().print(Panel(str(intt) ,title="Interfaces",  style="green"))
        for i in "************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)

        interface = input("\033[44mEnter your interface name: \033[0m").strip()
        for i in trc(range(100), style="blue", description="\033[5;31mLoading...\033[0m"):
            sp(0.03)
        cap = ps.LiveCapture(interface=interface, bpf_filter="ip")
        count = int(input("\033[44mHow many packets do you want to receive: \033[0m").strip())
        for i in trc(range(100), style="blue", description="\033[5;31mWorking...\033[0m"):
            sp(0.03)
        table = tab(title="Length", style="blue", box=ASCII2)
        table.add_column("Length of packets", style="white")
        
        try: 
            for i in cap.sniff_continuously(packet_count=count):
                if "DNS" in i:
                    table.add_row(str(i.length), "bytes")
            csl().print(table)
            
        except Exception as e:
            csl().print(Panel(str(e), title="Error", style="red"))
    except Exception as e:
        csl().print(Panel(str(e), style="red", title="Error"))


def site():
    try:
        logo = ff("Site")
        for i in logo:
            csl().print(i, style="purple", end="")
            sp(0.03)
        for i in "\n************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)
        
        interfaces = ps.LiveCapture().interfaces
        intt = []
        for i , n in enumerate(interfaces):
            intt.append(f"{i+1}. {n}")
        csl().print(Panel(str(intt) ,title="Interfaces",  style="green"))
        for i in "************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)

        interface = input("\033[44mEnter your interface name: \033[0m").strip()
        for i in trc(range(100), style="blue", description="\033[5;31mLoading...\033[0m"):
            sp(0.03)
        cap = ps.LiveCapture(interface=interface, bpf_filter="ip")
        count = int(input("\033[44mHow many packets do you want to receive: \033[0m").strip())
        for i in trc(range(100), style="blue", description="\033[5;31mWorking...\033[0m"):
            sp(0.03)
        table = tab(title="sites", style="blue", box=ASCII2)
        table.add_column("Site You opened", style="yellow")
        
        try: 
            for i in cap.sniff_continuously(packet_count=count):
                if "DNS" in i:
                    table.add_row(f"{i.dns.qry_name}")
                csl().print(table)
            
        except Exception as e:
            csl().print(Panel(str(e), title="Error", style="red"))
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))


def trans():
    try:
        logo = ff("Transport Layer")
        for i in logo:
            csl().print(i, style="purple", end="")
            sp(0.003)
        for i in "\n************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)
        
        interfaces = ps.LiveCapture().interfaces
        intt = []
        for i , n in enumerate(interfaces):
            intt.append(f"{i+1}. {n}")
        csl().print(Panel(str(intt) ,title="Interfaces",  style="green"))
        for i in "************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)

        interface = input("\033[44mEnter your interface name: \033[0m").strip()
        for i in trc(range(100), style="blue", description="\033[5;31mLoading...\033[0m"):
            sp(0.03)
        cap = ps.LiveCapture(interface=interface, bpf_filter="ip")
        count = int(input("\033[44mHow many packets do you want to receive: \033[0m").strip())
        for i in trc(range(100), style="blue", description="\033[5;31mWorking...\033[0m"):
            sp(0.03)
        table = tab(title="Transport Layer", style="blue", box=ASCII2)
        table.add_column("Layer", style="white")
        
        try: 
            for i in cap.sniff_continuously(packet_count=count):
                
                table.add_row(f"{i.transport_layer}", style="red")
            csl().print(table)
            
        except Exception as e:
            csl().print(Panel(str(e), title="Error", style="red"))
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))
def high():
    try: 
        logo = ff("Highest layer")
        for i in logo:
            csl().print(i, style="purple", end="")
            sp(0.003)
        for i in "\n************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)
        
        interfaces = ps.LiveCapture().interfaces
        intt = []
        for i , n in enumerate(interfaces):
            intt.append(f"{i+1}. {n}")
        csl().print(Panel(str(intt) ,title="Interfaces",  style="green"))
        for i in "************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)

        interface = input("\033[44mEnter your interface name: \033[0m").strip()
        for i in trc(range(100), style="blue", description="\033[5;31mLoading...\033[0m"):
            sp(0.03)
        cap = ps.LiveCapture(interface=interface, bpf_filter="ip")
        count = int(input("\033[44mHow many packets do you want to receive: \033[0m").strip())
        for i in trc(range(100), style="blue", description="\033[5;31mWorking...\033[0m"):
            sp(0.03)
        table = tab(title="Highest Layer", style="blue", box=ASCII2)
        table.add_column("Layer", style="white")
        
        try: 
            for i in cap.sniff_continuously(packet_count=count):
                
                table.add_row(f"{i.highest_layer}",style="green")
            csl().print(table)
            
        except Exception as e:
            csl().print(Panel(str(e), title="Error", style="red"))
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))

def all():
    try:

        logo = ff("All")
        for i in logo:
            csl().print(i, style="purple", end="")
            sp(0.003)
        for i in "\n************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)
        
        interfaces = ps.LiveCapture().interfaces
        intt = []
        for i , n in enumerate(interfaces):
            intt.append(f"{i+1}. {n}")
        csl().print(Panel(str(intt) ,title="Interfaces",  style="green"))
        for i in "************************************\n":
            csl().print(i, style="red", end="")
            sp(0.02)

        interface = input("\033[44mEnter your interface name: \033[0m").strip()
        for i in trc(range(100), style="blue", description="\033[5;31mLoading...\033[0m"):
            sp(0.03)
        cap = ps.LiveCapture(interface=interface, bpf_filter="ip")
        count = int(input("\033[44mHow many packets do you want to receive: \033[0m").strip())
        for i in trc(range(100), style="blue", description="\033[5;31mWorking...\033[0m"):
            sp(0.03)

        table = tab(title="All Details", style="blue", box=ASCII2)
        table.add_column("IP(src)", style="white")
        table.add_column("IP(dst)", style="green")
        table.add_column("Lenght of packets", style="red")
        table.add_column("Transport_Layer", style="purple")
        table.add_column("Highest_Layer", style="yellow")
        try: 
            for i in cap.sniff_continuously(packet_count=count):
                
                table.add_row(f"{i.ip.src}", f"{i.ip.dst}", f"{i.length} byts", f"{i.transport_layer}", f"{i.highest_layer}")
            csl().print(table)
            
        except Exception as e:
            csl().print(Panel(str(e), title="Error", style="red"))
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))



if args.i:
    try:
        ip()
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))
elif args.l:
    try:
        Dns()
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))
elif args.s:
    try:
        site()
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))
elif args.t:
    try:
        trans()
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))
elif args.hi:
    try:
        high()
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))
elif args.a:
    try:
        all()
    except Exception as e:
        csl().print(Panel(str(e), title="Error", style="red"))
else:
    csl().print(Panel("[bold red]You did'nt use any argument\nTry -h for more help"))
    exit(1)
