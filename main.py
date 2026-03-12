import json
import time
import random
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, Raw, conf
from scapy.layers.l2 import Ether

# --- CONFIGURATION ---
conf.verb = 0  # Silence Scapy warnings

class NetworkNode:
    def __init__(self, ip):
        self.ip = ip
        self.ports = set()
        self.protocols = set()
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.services = []
        self.risk_score = 0.0
        self.behavior_profile = "Normal"

class FlowEdge:
    def __init__(self, src, dst, proto, sport, dport):
        self.src = src
        self.dst = dst
        self.proto = proto
        self.sport = sport
        self.dport = dport
        self.count = 0

class DigitalTwinEngine:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.timeline = []

    def ingest_pcap(self, filename):
        print(f"[SYSTEM] Ingesting {filename}...")
        packets = rdpcap(filename)
        
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = pkt[IP].proto
                
                # Initialize Nodes
                self._ensure_node(src_ip)
                self._ensure_node(dst_ip)
                
                # Update Stats
                self.nodes[src_ip].bytes_sent += len(pkt)
                self.nodes[dst_ip].bytes_recv += len(pkt)
                
                # Protocol Analysis
                if TCP in pkt:
                    self.nodes[src_ip].ports.add(pkt[TCP].sport)
                    self.nodes[dst_ip].ports.add(pkt[TCP].dport)
                    self.nodes[src_ip].protocols.add("TCP")
                    self._add_edge(src_ip, dst_ip, "TCP", pkt[TCP].sport, pkt[TCP].dport)
                elif UDP in pkt:
                    self.nodes[src_ip].ports.add(pkt[UDP].sport)
                    self.nodes[dst_ip].ports.add(pkt[UDP].dport)
                    self.nodes[src_ip].protocols.add("UDP")
                    self._add_edge(src_ip, dst_ip, "UDP", pkt[UDP].sport, pkt[UDP].dport)
                
                # Service Fingerprinting (Heuristic)
                self._fingerprint_service(pkt)

        self._run_ai_analysis()
        return self.generate_json_output()

    def _ensure_node(self, ip):
        if ip not in self.nodes:
            self.nodes[ip] = NetworkNode(ip)

    def _add_edge(self, src, dst, proto, sport, dport):
        # Check if edge exists to aggregate
        for edge in self.edges:
            if edge.src == src and edge.dst == dst and edge.proto == proto:
                edge.count += 1
                return
        self.edges.append(FlowEdge(src, dst, proto, sport, dport))

    def _fingerprint_service(self, pkt):
        # Simple heuristic service detection
        if TCP in pkt:
            dport = pkt[TCP].dport
            if dport == 22: self.nodes[pkt[IP].dst].services.append("SSH")
            elif dport == 80: self.nodes[pkt[IP].dst].services.append("HTTP")
            elif dport == 443: self.nodes[pkt[IP].dst].services.append("HTTPS")
            elif dport == 3389: self.nodes[pkt[IP].dst].services.append("RDP")

    def _run_ai_analysis(self):
        """
        Simulates the AI/ML Behavioral Analysis.
        In a real system, this would feed into a PyTorch/TensorFlow model.
        """
        print("[AI] Running Behavioral Heuristics...")
        for ip, node in self.nodes.items():
            score = 0.0
            
            # Heuristic 1: Port Hopping (Potential Scanning)
            if len(node.ports) > 10:
                score += 30
                node.behavior_profile = "Reconnaissance"
            
            # Heuristic 2: High Entropy Traffic (Potential Exfil)
            if node.bytes_sent > 1000000: # Arbitrary threshold
                score += 20
                node.behavior_profile = "High Volume"
            
            # Heuristic 3: Unusual Ports
            if 1024 not in node.ports and len(node.ports) > 0:
                 score += 10

            node.risk_score = min(100, score)
            
            if node.risk_score > 40:
                node.behavior_profile = "Anomalous"

    def generate_json_output(self):
        data = {
            "nodes": [
                {
                    "id": ip,
                    "ports": list(node.ports),
                    "services": node.services,
                    "risk": node.risk_score,
                    "profile": node.behavior_profile,
                    "bytes": node.bytes_sent + node.bytes_recv
                }
                for ip, node in self.nodes.items()
            ],
            "links": [
                {
                    "source": e.src,
                    "target": e.dst,
                    "type": e.proto,
                    "weight": e.count
                }
                for e in self.edges
            ],
            "meta": {
                "total_hosts": len(self.nodes),
                "total_flows": len(self.edges),
                "timestamp": time.time()
            }
        }
        return data

# --- EXECUTION ---
if __name__ == "__main__":
    # You would point this to a real .pcap file
    # For demo purposes, we will simulate a PCAP load if file doesn't exist
    try:
        engine = DigitalTwinEngine()
        # result = engine.ingest_pcap("capture.pcap") 
        # For this demo, we will mock the result to show the UI
        result = {
            "nodes": [
                {"id": "192.168.1.10", "ports": [22, 80, 443], "services": ["SSH", "HTTP"], "risk": 5, "profile": "Normal", "bytes": 5000},
                {"id": "192.168.1.15", "ports": [22, 23, 80, 443, 3306, 5432, 8080, 9000, 1234, 5678, 9999], "services": ["SSH", "Telnet"], "risk": 85, "profile": "Reconnaissance", "bytes": 12000},
                {"id": "10.0.0.5", "ports": [443], "services": ["HTTPS"], "risk": 10, "profile": "Normal", "bytes": 50000000}
            ],
            "links": [
                {"source": "192.168.1.10", "target": "10.0.0.5", "type": "TCP", "weight": 150},
                {"source": "192.168.1.15", "target": "192.168.1.10", "type": "TCP", "weight": 500}
            ],
            "meta": {"total_hosts": 3, "total_flows": 2, "timestamp": time.time()}
        }
        print("[SYSTEM] Analysis Complete. Generating UI Data...")
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}")