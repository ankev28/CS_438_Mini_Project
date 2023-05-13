import flet as ft
import socket
from scapy.all import *
import psutil
import sys
import subprocess
from uuid import getnode as get_mac
import threading

hostname=socket.gethostname()
IPAddr=socket.gethostbyname(hostname)
index = 0
selectedIndex = 0
PAGEPTR = None
dtPTR = None
lvPTR = None
bsPTR = None

dog = None
currentPIDS={}
print(hostname)
print(IPAddr)

packets = []
recording = True

def get_pid(portNo):
    connections = psutil.net_connections()
    port = int(portNo)
    for con in connections:
        if con.raddr != tuple():
            if con.raddr.port == port:
                return con.pid, con.status
        if con.laddr != tuple():
            if con.laddr.port == port:
                return con.pid, con.status
    return ("N/A", "N/A")


def handler(packet):
    global PAGEPTR, dtPTR, lvPTR, index
    srcIP = None
    destIP = None
    srcPort = None
    destPort = None
    process_name = "N/A"
    protocol_name = ""
    ip_type = ""
    # try:
    if IP in packet:
        ip_type = "IPv4"
        srcIP = packet[IP].src
        destIP = packet[IP].dst
    elif IPv6 in packet:
        ip_type = "IPv6"
        srcIP = packet[IPv6].src
        destIP = packet[IPv6].dst
        print("ipv6 packet detected") # note, it was very rare to find ipv6 packets even when we tested with wireshark at beckman institute
    else:
        return
    
    if TCP in packet:
        protocol_name = "TCP"
        srcPort = packet[TCP].sport 
        destPort = packet[TCP].dport
    elif UDP in packet:
        protocol_name = "UDP"
        srcPort = packet[UDP].sport 
        destPort = packet[UDP].dport
    else:
        return
    
    if srcIP == str(IPAddr):
        pid = get_pid(srcPort)
        if (pid[0] == "N/A"):
            return
        process = psutil.Process(pid[0])
        process_name = process.name()

    elif destIP == str(IPAddr):
        pid = get_pid(destPort)
        if (pid[0] == "N/A"):
            return
        process = psutil.Process(pid[0])
        process_name = process.name()
    elif IPv6 in packet:
        try:
            summary = packet.summary()
            summary = summary.split(" / ")
            useData = summary[2]
            useData = useData.split(" ")

            srcDataSplit = useData[1].split(":")
            destDataSplit = useData[3].split(":")
            srcIP = ""
            for i in range(len(srcDataSplit)-1):
                srcIP += srcDataSplit[i]
            srcPort = srcDataSplit[-1]
            destIP = ""
            for i in range(len(destDataSplit)-1):
                destIP += destDataSplit[i]
            destPort = destDataSplit[-1]

            pid = ("N/A", "N/A")

        except: 
            print("exception decoding ipv6 metadata")
            return
    else:
        print("unknown ip type")
        return
    
    raw_payload = ""
    if Raw in packet:
        raw_payload = packet[Raw].load
    packets.append((ip_type, srcIP, destIP, srcPort, destPort, protocol_name, process_name, pid[0], pid[1], raw_payload))

    dt = dtPTR.rows

    def showData(e):
        dataPos = int(e.control.cells[0].content.value)
        create_bs(packets[dataPos])

    dt += [
                ft.DataRow(
                    cells=[
                        ft.DataCell(ft.Text(index)),
                        ft.DataCell(ft.Text(ip_type)),
                        ft.DataCell(ft.Text(srcIP)),
                        ft.DataCell(ft.Text(destIP)),
                        ft.DataCell(ft.Text(srcPort)),
                        ft.DataCell(ft.Text(destPort)),
                        ft.DataCell(ft.Text(protocol_name)),
                        ft.DataCell(ft.Text(len(packet))),
                        ft.DataCell(ft.Text(pid[0])),
                    ], on_long_press = showData) 
            ]
    index += 1
    PAGEPTR.update()

def fab_pressed(e):
    global recording 
    recording = False
    return

def filter(p):
    global recording 
    return not recording

def create_bs(content):
    global bsPTR, PAGEPTR
    if bsPTR == None:
        pass
    elif bsPTR.open == True:
        PAGEPTR.overlay.pop()

    bsPTR = ft.BottomSheet(
        ft.Container(
            ft.Column(
                [
                    ft.Text("Internet Protocol Version: " + str(content[0])),
                    ft.Text("Source IP Address: " + str(content[1])),
                    ft.Text("Destination IP Address: " + str(content[2])),
                    ft.Text("Source Port: " + str(content[3])),
                    ft.Text("Destination Port: " + str(content[4])),
                    ft.Text("Transport Protocol: " + str(content[5])),
                    ft.Text("Host Application: " + str(content[6])),
                    ft.Text("Process ID Number: " + str(content[7])),
                    ft.Text("Additional Connection Information: " + str(content[8])), 
                    ft.Text("Payload (bytes): " + str(content[9]))
                ],
                tight=True,
            ),
            padding=20,
        ),
        open=True
    )
    PAGEPTR.overlay.append(bsPTR)
    PAGEPTR.update()
    bsPTR.update()

def close_bs():
    global bsPTR
    bsPTR.open = False
    bsPTR.update()

def main(page: ft.Page):
    global PAGEPTR, dtPTR, lvPTR, packets
    PAGEPTR = page
    PAGEPTR.floating_action_button = ft.FloatingActionButton(
        icon=ft.icons.STOP_SHARP, on_click=fab_pressed, bgcolor=ft.colors.BLACK38
    )
    PAGEPTR.title = "Packets detected at " + hostname
    lv = ft.ListView(expand=1, spacing=10, padding=20, auto_scroll=False)
    dt = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("ID #")),
                ft.DataColumn(ft.Text("IP")),
                ft.DataColumn(ft.Text("Source IP")),
                ft.DataColumn(ft.Text("Destination IP")),
                ft.DataColumn(ft.Text("Source port")),
                ft.DataColumn(ft.Text("Destination port")),
                ft.DataColumn(ft.Text("Transport Protocol")),
                ft.DataColumn(ft.Text("Length")),
                ft.DataColumn(ft.Text("PID")),
            ],
            rows=[], # will fill dynamically
        )
    lv.controls.append(dt)
    PAGEPTR.add(lv)
    
    lvPTR = lv
    dtPTR = dt
    t = threading.Thread(target=sniff, kwargs={"prn": handler, "store": 0, "stop_filter": filter})
    t.daemon = True
    t.start()

if __name__ == "__main__":
    ft.app(target=main)
