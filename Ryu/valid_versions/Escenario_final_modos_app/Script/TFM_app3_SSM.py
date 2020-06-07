######################################################

######################################
# Application for the global scenario SDN in mode SSM #
######################################

#Name:        SwitchIGMPv3ModeSSM

#Description: Application that manages a switch to be a proxy multicast using IGMPv3 
#            to provide multicast traffic from two providers to different clients using 
#            mode SSM of the controller 

#Author:      Sandra Garcia
######################################################

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import igmp
from collections import defaultdict

class SwitchIGMPv3ModeSSM(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchIGMPv3ModeSSM, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self._to_hosts = {}
        self.serv_ip_to_port = {'10.100.0.21': '5', '10.100.0.22': '6'}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Removes any flows that might have been stuck
        match = parser.OFPMatch()
        actions = []
        self.del_flow(datapath, 0, None, match, actions)

        # install table-miss flow entry
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, command=ofproto.OFPFC_ADD,     
                                    priority=priority, match=match,  
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, priority, out_port, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, 
                                    command=ofproto.OFPFC_DELETE, out_port=out_port, 
                                    out_group=ofproto.OFPG_ANY, priority=priority, 
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, 
                                    command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, 
                                    out_group=ofproto.OFPG_ANY, match=match, 
                                    instructions=inst)
        datapath.send_msg(mod)

    def do_join_SSM(self, igmp_in, in_port, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        record = igmp_in.records[0]
        grp_addr = record.address
        actions = []
        server_ip = record.srcs[0]
        server_port = int(self.serv_ip_to_port[server_ip])
        
        #To send both messages
        actions = [parser.OFPActionOutput(server_port)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)
        actions = []

        if not self._to_hosts[dpid].get(grp_addr):
            self._to_hosts[dpid].setdefault(grp_addr, {'servers': {}})
        if not self._to_hosts[dpid][grp_addr]['servers'].get(server_ip):
            self._to_hosts[dpid][grp_addr]['servers'][server_ip] = {'ports': {}}
        if not self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports'].get(in_port):
            self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports'][in_port] = {'out': False}
            for port in self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports']:
                actions.append(parser.OFPActionOutput(port))
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr, ipv4_src=server_ip)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        if not self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports'][in_port]['out']:
            self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports'][in_port]['out'] = True
            print("Flow added")

    def do_leave_SSM(self, igmp_in, in_port, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        record = igmp_in.records[0]
        grp_addr = record.address
        actions = []
        server_ip = record.srcs[0]
        server_port = int(self.serv_ip_to_port[server_ip])

        #To send both messages
        actions = [parser.OFPActionOutput(server_port)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)
        actions = []

        # It sends 2 Leave messages, the second must be ignored
        if len(self._to_hosts[dpid]) == 0:
            return
        if not self._to_hosts[dpid].get(grp_addr):
            return
        if not self._to_hosts[dpid][grp_addr]['servers'].get(server_ip):
            return
        if not self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports'].get(in_port):
            return

        if self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports'][in_port]['out']:
            self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports'][in_port]['out'] = False
        if self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports'].get(in_port):
            del self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports'][in_port]
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr, ipv4_src=server_ip)
            if len(self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports']) == 0:
                self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
            else:
                for port in self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports']:
                    actions.append(parser.OFPActionOutput(port))
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        if len(self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports']) == 0:
            del self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports']
        if len(self._to_hosts[dpid][grp_addr]['servers'][server_ip]) == 0:
            del self._to_hosts[dpid][grp_addr]['servers'][server_ip]
        if len(self._to_hosts[dpid][grp_addr]['servers']) == 0:
            del self._to_hosts[dpid][grp_addr]['servers']
        if len(self._to_hosts[dpid][grp_addr]) == 0:
            del self._to_hosts[dpid][grp_addr]
        print("Flow updated")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        igmp_in = pkt.get_protocol(igmp.igmp)
        udp = pkt.protocols[2]
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if(igmp_in):    #Check if the packet is IGMP
            record = igmp_in.records[0]
            log = "SW=%s PORT=%d IGMP received. " % (dpid_to_str(dpid), in_port)
            if(igmp_in.msgtype==0x22):
                print("IGMPv3 Membership Report")
                if(record.srcs!=[] and record.type_==3):
                    print("IGMPv3 Join Group SSM")
                    self.logger.info(log + "[Join SSM]")
                    self.do_join_SSM(igmp_in, in_port, msg)
                elif(record.srcs!=[] and record.type_==6):
                    print("IGMPv3 Leave Group SSM")
                    self.logger.info(log + "[Leave SSM]")
                    self.do_leave_SSM(igmp_in, in_port, msg)
                else:
                    print("Choose the correct configuration")    
        elif(udp and dst[:8] == '01:00:5e'): #Prints when no client is listening in the multicast group
            print("No clients listening")
        else: #Normal switch - Example simple_switch_13.py
            #learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            print(self.mac_to_port)
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
