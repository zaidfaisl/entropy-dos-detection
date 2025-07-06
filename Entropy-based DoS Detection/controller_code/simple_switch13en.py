# simple_switch_with_entropy.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
import csv
import os
import time
from entropy_module import EntropyModule

class SimpleSwitchWithEntropy(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchWithEntropy, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.entropy = EntropyModule(window_size=100, max_windows=10)
        self.start_time = time.time()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.csv_file = os.path.join(script_dir, "entropy_results100.csv")
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
            entropy = self.entropy.add_and_check(dst_ip)

            if entropy is not None:
                timestamp = round(time.time() - self.start_time, 2)
                status = 'Attack' if self.entropy.threshold and entropy < self.entropy.threshold else 'Normal'

                with open(self.csv_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, entropy])

                self.logger.info(f"[*] Time: {timestamp}s | Entropy: {entropy:.4f} | Threshold: {self.entropy.threshold:.4f}" if self.entropy.threshold else f"[*] Time: {timestamp}s | Entropy: {entropy:.4f} | Threshold: N/A")
                if self.entropy.threshold and status == 'Attack':
                    self.logger.warning("[!!!] DDoS Attack Detected!")
                elif self.entropy.threshold:
                    self.logger.info("[\u2713] Normal Traffic")

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

