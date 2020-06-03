######################################################

######################################
# Application for basic scenario SDN #
######################################

#Name:        SwitchIGMP13

#Description: Application that manages a switch to be a proxy multicast using IGMP querier mode 
#            to provide multicast traffic from a server to different clients

#Author:      Sandra Garcia
######################################################

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import igmp
from ryu.lib import igmplib
from ryu.lib.dpid import str_to_dpid
from collections import defaultdict

class SwitchIGMP13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'igmplib': igmplib.IgmpLib}

    def __init__(self, *args, **kwargs):
        super(SwitchIGMP13, self).__init__(*args, **kwargs)
        self._snoop = kwargs['igmplib']
        self._snoop.set_querier_mode(dpid=str_to_dpid('0000000000000001'), server_port=5)
        self.mac_to_port = {}
        self.grp_to_port = defaultdict(list)

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

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

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
        
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if(igmp_in):    #Check if the packet is IGMP
            grp_addr = igmp_in.address
            match = parser.OFPMatch(eth_dst=dst, eth_type=0x0800,ip_proto=17)
            actions = []
            if(src=='00:00:00:00:00:01'): #Message from switch - query
                print("IGMPv2 query")
                return
            elif(igmp_in.msgtype==0x16): #IGMPv2 report (Join) message 
                print("IGMPv2 Report")
                #Add in_port to grp_to_mac table
                if in_port not in self.grp_to_port[grp_addr]:
                    self.grp_to_port[grp_addr].append(in_port)
                    for port in self.grp_to_port[grp_addr]:
                        actions.append(parser.OFPActionOutput(port))
                    print("Flow added")
            elif(igmp_in.msgtype==0x17): #IGMPv2 leave message 
                print("IGMPv2 Leave Group")
                if in_port in self.grp_to_port[grp_addr]:
                    self.grp_to_port[grp_addr].remove(in_port)
                    if len(self.grp_to_port[grp_addr]) == 0:
                        del self.grp_to_port[grp_addr]
                    else:
                        print("Still other clients listening")
                    print("Flow updated")
        elif(not igmp_in and dst[:8] == '01:00:5e'): #Prints when no client is listening in the multicast group
            print("No clients listening")
        else: #Normal switch - Example simple_switch_13.py
            #learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            #print(self.mac_to_port)
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

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

            