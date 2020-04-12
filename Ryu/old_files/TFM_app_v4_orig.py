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
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import igmp
#from ryu.lib import igmplib
#from ryu.lib.packet import ipv4
from collections import defaultdict

class SimpleSwitchIGMP13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {'igmplib': igmplib.IgmpLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchIGMP13, self).__init__(*args, **kwargs)
        self.mac_to_port = {} #Only used for not IGMP msg
        self.grp_to_mac = defaultdict(list) #change name grp_to_clt
        self.server_to_mac = defaultdict(list) #change name grp_to_server
        self.server_to_client = defaultdict(list) 
        #self.serv_to_clt = {'10.100.10.1': '2, 3', '10.100.10.2': '4, 5'}
        #self.serv_to_clt = {'2': '10.100.10.1', '3': '10.100.10.1', '4': '10.100.10.2', '5': '10.100.10.2'}
        self.serv_to_clt = {'2': '6', '3': '6', '4': '7', '5': '7'}
        self.clt_to_server = {'6': (2, 3), '7': (4, 5)}

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

    def del_flow(self, datapath, priority, out_port, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS,
                                             actions)]
        if buffer_id:
            #mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, command=ofproto.OFPFC_DELETE, out_port=out_port, out_group=ofproto.OFPG_ANY, priority=priority, match=match, instructions=inst)
        else:
            #mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, command=ofproto.OFPFC_DELETE, out_port=out_port, out_group=ofproto.OFPG_ANY, match=match, instructions=inst)
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
        #ipv4_in = pkt.get_protocol(ipv4.ipv4)

        #print("\n")

        #print(msg)

        #print(pkt)

        #print(igmp_in)

        #print(ipv4_in)

        eth_type = eth.ethertype
        dst = eth.dst
        src = eth.src

        #print("Ethertype",eth_type)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        #print(self.serv_to_clt)

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if(igmp_in):    #Check if pkt is IGMP control
            grp_addr = igmp_in.address
            #src_addr = ipv4_in.src
            #print(src_addr)
            match = parser.OFPMatch(eth_dst=dst, eth_type=0x0800,ip_proto=17)
            actions = []
            server = int(self.serv_to_clt[str(in_port)])
            if(igmp_in.msgtype==0x16):
                print("IGMPv2 Report")
                #print(in_port)
                #Add in_port to grp_to_mac table
                if in_port not in self.grp_to_mac[grp_addr]:
                    self.grp_to_mac[grp_addr].append(in_port)
                    #for port in self.grp_to_mac[grp_addr]:
                        #print(port)
                    #actions.append(parser.OFPActionOutput(in_port))
                    #server = int(self.serv_to_clt[str(in_port)])
                    #print(type(server))
                    #print(self.server_to_mac)
                    port_server = self.server_to_mac[grp_addr]
                    self.server_to_client[server].append(in_port)
                    print(self.server_to_client)
                    #print(port_server)
                    #for port in port_server:
                    #	if int(server)==port:
                    #		print("Already server")
                    if server not in port_server:
                    	self.server_to_mac[grp_addr].append(server)
                    	print("new server")
                    	actions.append(parser.OFPActionOutput(in_port))
                    	match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=server, ipv4_dst=grp_addr)
                    	self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    	print("Flow added")
                    else:
                    	print("already a client listening")
                    	group_ports = self.grp_to_mac[str(grp_addr)]
                    	#print(group_ports)
                    	print(self.clt_to_server[str(server)])
                    	port_clients_server = self.clt_to_server[str(server)]
                    	for port in port_clients_server:
                    		#print(port)
                    		if port==in_port:
                    		#	print(port)
                    			print("Is from this server")
                    			#actions.append(parser.OFPActionOutput(port))
                    	#if port_clients_server==in_port:
                    		
                    	for port in group_ports:
                    	#	print(port)
                    		actions.append(parser.OFPActionOutput(port))
                    	match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=server, ipv4_dst=grp_addr)
                    	self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    	print("Flow added")
                    #if port_server in self.server_to_mac[grp_addr]:
                    #	print("already a client listening")	
                    #elif port_server not in self.server_to_mac[grp_addr]:
                    #	self.server_to_mac[grp_addr].append(int(server))
                    #	print("new")
                    print(port_server)
                    print(self.server_to_mac)
                        #match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr, ipv4_src=(server, src_addr))
                    #match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr, ipv4_src=server)
                            #match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr)
                    #print(self.serv_to_clt.get(str(in_port)))
                    #print(self.serv_to_clt[str(in_port)])
                    #for port in self.serv_to_clt.values():
                        #if in_port==port:
                            #print(port)
                            #print("Yes")
                    #if(in_port==2 or in_port==3):
                        #match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr, ipv4_src="10.100.10.1")
                        #actions.append(parser.OFPActionOutput(in_port))
                        #print("Yes")
                    #elif (in_port==4 or in_port==5):
                        #match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr, ipv4_src="10.100.10.2")
                        #actions.append(parser.OFPActionOutput(in_port))
                    #self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    #group_ports = self.grp_to_mac[str(grp_addr)]
                    #print(group_ports)
                    #for port in group_ports:
                    #actions.append(parser.OFPActionOutput(in_port))
                    #print(actions)
                    #match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=server, ipv4_dst=grp_addr)
                    #print(match)
                    #self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    #print("Flow added")
                    print(self.grp_to_mac)
            elif(igmp_in.msgtype==0x17): 
                print("IGMPv2 Leave Group")
                if in_port in self.grp_to_mac[grp_addr]:
                    match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=server, ipv4_dst=grp_addr)
                    #print(server)
                    #print(actions)
                    #self.del_flow(datapath, 1, match, actions, msg.buffer_id)
                    self.grp_to_mac[grp_addr].remove(in_port)
                    print(self.grp_to_mac.values())
                    if len(self.grp_to_mac[grp_addr]) == 0:
                        print("Empty group")
                        del self.grp_to_mac[grp_addr]
                        self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
                    else:
                        print("Still other clients")
                        for port in self.grp_to_mac[grp_addr]:
                            actions.append(parser.OFPActionOutput(port))
                            #match = parser.OFPMatch(eth_src=src, eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr, ipv4_src="10.100.10.1")
                        self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
                    print("Flow updated")
                    print(self.grp_to_mac)
        elif(not igmp_in and dst[:8] == '01:00:5e'):    #Check if pkt is IGMP data
            print("IGMP DATA!")
        else: #Normal l2 switching
           # print("Other information")
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
