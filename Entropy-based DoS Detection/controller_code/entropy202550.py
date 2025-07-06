from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from collections import Counter
import math
import csv
import os
import time

WINDOW_SIZE = 50
MAX_WINDOWS = 10

class L3SwitchWithEntropyDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3SwitchWithEntropyDetection, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.buffer = []
        self.entropy_history = []
        self.threshold = None
        self.start_time = time.time()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.csv_file = os.path.join(script_dir, "entropy_results50.csv")
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Time (s)', 'Entropy'])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip:
            dst_ip = ip.dst
            self.buffer.append(dst_ip)

            if len(self.buffer) == WINDOW_SIZE:
                entropy = self.calculate_entropy(self.buffer)
                self.entropy_history.append(entropy)

                if len(self.entropy_history) == MAX_WINDOWS and self.threshold is None:
                    self.threshold = sum(self.entropy_history) / MAX_WINDOWS
                    self.logger.info(f"[*] Threshold established after warmup: {self.threshold:.4f}")

                timestamp = round(time.time() - self.start_time, 2)
                status = 'Attack' if self.threshold is not None and entropy < self.threshold else 'Normal'

                with open(self.csv_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, entropy])

                self.logger.info(f"[*] Time: {timestamp}s | Entropy: {entropy:.4f} | Threshold: {self.threshold:.4f}" if self.threshold else f"[*] Time: {timestamp}s | Entropy: {entropy:.4f} | Threshold: N/A")
                if self.threshold is not None and status == 'Attack':
                    self.logger.warning("[!!!] DDoS Attack Detected!")
                elif self.threshold is not None:
                    self.logger.info("[✓] Normal Traffic")

                self.buffer = []

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1,
                          parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src),
                          actions, msg.buffer_id)
            return
        else:
            data = msg.data if msg.data else None
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    def calculate_entropy(self, window):
        freq = Counter(window)
        total = len(window)
        entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())
        return entropy

