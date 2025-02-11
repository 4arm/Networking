import socket
import psutil
from flask import Flask, render_template, request
import nmap
from scapy.all import ARP, send, sniff, IP, DNS, TCP
import time
import threading
import plotly.graph_objs as go
import plotly.io as pio

app = Flask(__name__)

captured_packets = []
network_usage_data = {'upload': [], 'download': [], 'time': []}
protocol_counts = {'http': 0, 'dns': 0, 'tcp': 0, 'udp': 0}

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))  # Connect to Google's DNS to get the local IP
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

def scan_network(subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')  # Ping scan to detect active hosts

    devices = []
    for host in nm.all_hosts():
        mac = nm[host]['addresses'].get('mac', 'N/A')
        device_name = nm[host]['hostnames'] if nm[host]['hostnames'] else 'N/A'
        model = nm[host].get('osmatch', 'N/A')
        gateway = nm[host].get('hostnames', {'name': '', 'type': ''})
        devices.append({
            'ip': nm[host]['addresses'].get('ipv4', 'N/A'),
            'mac': mac,
            'status': nm[host]['status']['state'],
            'device_name': device_name,
            'model': model,
            'gateway': gateway
        })
    return devices

def arp_spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)
    send(packet, verbose=False)
    return f"Sent ARP spoofing packet to {target_ip}, spoofing {spoof_ip}"

def packet_sniffer(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        payload = packet.summary()
        captured_packets.append({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'proto': proto,
            'payload': payload
        })

        # Track protocol counts
        if proto == 6:  # TCP
            protocol_counts['tcp'] += 1
        elif proto == 17:  # UDP
            protocol_counts['udp'] += 1
        elif packet.haslayer(DNS):  # DNS
            protocol_counts['dns'] += 1
        elif packet.haslayer(TCP) and packet[TCP].dport == 80:  # HTTP
            protocol_counts['http'] += 1

def monitor_network_usage():
    while True:
        net_io = psutil.net_io_counters()
        upload = net_io.bytes_sent / 1024  # Convert to KB
        download = net_io.bytes_recv / 1024  # Convert to KB
        timestamp = time.strftime('%H:%M:%S')
        
        network_usage_data['upload'].append(upload)
        network_usage_data['download'].append(download)
        network_usage_data['time'].append(timestamp)

        if len(network_usage_data['time']) > 30:  # Limit to last 30 records
            network_usage_data['upload'].pop(0)
            network_usage_data['download'].pop(0)
            network_usage_data['time'].pop(0)
        
        time.sleep(1)  # Update every second

def generate_network_graph():
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=network_usage_data['time'], y=network_usage_data['upload'], mode='lines', name='Upload (KB/s)'))
    fig.add_trace(go.Scatter(x=network_usage_data['time'], y=network_usage_data['download'], mode='lines', name='Download (KB/s)'))
    fig.update_layout(title='Network Usage Over Time', xaxis_title='Time', yaxis_title='Data (KB/s)')
    graph_html = pio.to_html(fig, full_html=False)
    return graph_html

def generate_protocol_distribution():
    labels = list(protocol_counts.keys())
    values = list(protocol_counts.values())
    fig = go.Figure(data=[go.Pie(labels=labels, values=values)])
    fig.update_layout(title='Protocol Distribution')
    graph_html = pio.to_html(fig, full_html=False)
    return graph_html

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/network_scan", methods=["GET", "POST"])
def network_scan():
    devices = []
    local_ip = get_local_ip()  # Get local IP address
    if request.method == "POST":
        subnet = request.form["subnet"]
        devices = scan_network(subnet)
    graph_html = generate_network_graph()
    return render_template("network_scan.html", devices=devices, local_ip=local_ip, graph_html=graph_html)

@app.route("/packet_sniffing", methods=["GET", "POST"])
def packet_sniffing():
    if request.method == "POST":
        sniff(prn=packet_sniffer, store=False, count=10)
    protocol_graph_html = generate_protocol_distribution()
    return render_template("packet_sniffing.html", packets=captured_packets, protocol_graph_html=protocol_graph_html)

@app.route("/network_usage")
def network_usage():
    graph_html = generate_network_graph()  # Generate graph
    return render_template("network_usage.html", graph_html=graph_html)

if __name__ == "__main__":
    threading.Thread(target=monitor_network_usage, daemon=True).start()
    app.run(debug=True)
