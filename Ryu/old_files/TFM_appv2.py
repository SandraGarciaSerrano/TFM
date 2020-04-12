# Written by Daniel de Villiers (2019)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
#from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types
from ryu.lib.packet import igmp
from ryu.lib import igmplib
from ryu.lib.dpid import str_to_dpid
from collections import defaultdict
#from getmac import get_mac_address

class SimpleSwitchIGMP13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {'igmplib': igmplib.IgmpLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchIGMP13, self).__init__(*args, **kwargs)
        #self._snoop = kwargs['igmplib']
        #self._snoop.set_querier_mode(dpid=str_to_dpid('0000000000000001'), server_port=6)
        #self._snoop.set_querier_mode(dpid=str_to_dpid('0000000000000001'), server_port=7)
        self.mac_to_port = {}
        self.grp_to_mac = defaultdict(list)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
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
        #print(mod)
        datapath.send_msg(mod)

    def del_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Overwrites the action of the add_flow
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
            #mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, command=ofproto.OFPFC_DELETE, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
            #mod = parser.OFPFlowMod(datapath=datapath, priority=priority, command=ofproto.OFPFC_DELETE, match=match, instructions=inst)
     #     #  mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, priority=1, match=match)
        #print(mod)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        igmp_in = pkt.get_protocol(igmp.igmp)
        #udp = pkt.get_protocol(udp.udp)
        udp = pkt.protocols[2]

        print(self.grp_to_mac)

        print("\n")

        print(pkt)

        print(udp)

        print ("\n")

        print(igmp_in)

        eth_type = eth.ethertype
        dst = eth.dst
        src = eth.src

        print("Ethertype",eth_type)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if(igmp_in):    #Check if pkt is IGMP control
            #grp_record = igmp_in.records[0]
            #grp_addr = grp_record.address
            grp_addr = igmp_in.address
            print(grp_addr)
            #mc = addrconv.ipv4.text_to_bin(grp_addr)
            #print(mc)
            #mac_grp_addr = get_mac_address(ip=grp_addr)
            #print(mac_grp_addr)
            #match = parser.OFPMatch(eth_dst=dst, eth_type=0x0800,ip_proto=17)
            actions = []
            #if(src=='00:00:00:00:00:01'):
            #    print("IGMPv2 query")
            #    return
            #if(igmp_in.msgtype==0x22 and grp_record.type_==4):
            if(igmp_in.msgtype==0x16):
                print("IGMPv3 Report - Join")
                #Add in_port to grp_to_mac table
                if in_port not in self.grp_to_mac[grp_addr]:
                    self.grp_to_mac[grp_addr].append(in_port)
                    for port in self.grp_to_mac[grp_addr]:
                        #match = datapath.ofproto_parser.OFPMatch(ipv4_dst=grp_addr)
                        actions.append(parser.OFPActionOutput(port))
                        print(actions)
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=grp_addr)
                    print(match)
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    print("Flow added")
                    print(self.grp_to_mac)
                else:
                    print("Flow already added - duplicate message")
            #elif(igmp_in.msgtype==0x22 and grp_record.type_==3):
            elif(igmp_in.msgtype==0x17):
                print("IGMPv3 Report - Leave")
                if in_port in self.grp_to_mac[grp_addr]:
                    #match = datapath.ofproto_parser.OFPMatch(in_port=in_port)
                    #actions.append(parser.OFPActionOutput(in_port))
                    match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=grp_addr)
                    print(actions)
                    self.del_flow(datapath, 1, match, actions, msg.buffer_id)
                    print(actions)
                    #self.del_flow(datapath, 1, actions)
                    self.grp_to_mac[grp_addr].remove(in_port)
                    print(self.grp_to_mac.values())
                    if len(self.grp_to_mac[grp_addr]) == 0:
                        print("Empty")
                        del self.grp_to_mac[grp_addr]
                    else:
                        print("Still other clients")

                    print("Flow updated")
                    print(self.grp_to_mac)
        elif(not igmp_in and dst[:8] == '01:00:5e'):    #Check if pkt is IGMP data
            print("IGMP DATA!")
        else: #Normal l2 switching
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
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
