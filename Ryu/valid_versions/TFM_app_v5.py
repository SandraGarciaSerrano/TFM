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
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import igmp
#from ryu.lib import igmplib
from collections import defaultdict

class SimpleSwitchIGMP13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {'igmplib': igmplib.IgmpLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchIGMP13, self).__init__(*args, **kwargs)
        #self._snoop = kwargs['igmplib']
        self.mac_to_port = {}
        self._to_hosts = {}
        #self.grp_to_mac = defaultdict(list)
        self.serv_to_clt = {'2': '6', '3': '6', '4': '7', '5': '7'}

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
        actions = []
        self.del_flow(datapath, 0, None, match, actions)
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
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, command=ofproto.OFPFC_DELETE, out_port=out_port, out_group=ofproto.OFPG_ANY, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match, instructions=inst)
        datapath.send_msg(mod)

    def do_report(self, igmp_in, in_port, msg):
        datapath = msg.datapath
        #ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #in_port = msg.match['in_port']
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        grp_addr = igmp_in.address
        actions = []
        server = int(self.serv_to_clt[str(in_port)])

        if not self._to_hosts[dpid].get(grp_addr):
            self._to_hosts[dpid].setdefault(grp_addr, {'servers': {}})
            #print(self._to_hosts)
            #print("New group")

        if not self._to_hosts[dpid][grp_addr]['servers'].get(server):
            #self._to_hosts[dpid][grp_addr]['servers'].setdefault(server, {'ports': {}})
            self._to_hosts[dpid][grp_addr]['servers'][server] = {'ports': {}}
            #print(self._to_hosts)
            #print("New server")

        if not self._to_hosts[dpid][grp_addr]['servers'][server]['ports'].get(in_port):
            self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port] = {'out': False}
            #self._to_hosts[dpid][grp_addr][server]['ports'].setdefault(in_port, {'out': False, 'in': False})
            for port in self._to_hosts[dpid][grp_addr]['servers'][server]['ports']:
                print(port)
                actions.append(parser.OFPActionOutput(port))
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=server, ipv4_dst=grp_addr)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=in_port, ipv4_dst=grp_addr)
            actions = [parser.OFPActionOutput(server)]
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            #print(self._to_hosts)
            #print("New port")

        if not self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port]['out']:
            self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port]['out'] = True
            print(self._to_hosts)
            print("Flow added")

    def do_leave(self, igmp_in, in_port, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        grp_addr = igmp_in.address
        actions = []
        server = int(self.serv_to_clt[str(in_port)])

        if self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port]['out']:
            self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port]['out'] = False
            #print(self._to_hosts)
            #print("Port by defect")

        if self._to_hosts[dpid][grp_addr]['servers'][server]['ports'].get(in_port):
            print('Remove port')
            del self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port]
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=server, ipv4_dst=grp_addr)
            if len(self._to_hosts[dpid][grp_addr]['servers'][server]['ports']) == 0:
                self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=in_port, ipv4_dst=grp_addr)
                self.del_flow(datapath, 1, server, match, actions, msg.buffer_id)
            else:
                for port in self._to_hosts[dpid][grp_addr]['servers'][server]['ports']:
                    actions.append(parser.OFPActionOutput(port))
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                actions = []
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=in_port, ipv4_dst=grp_addr)
                self.del_flow(datapath, 1, server, match, actions, msg.buffer_id)
            
            print(self._to_hosts)

        if len(self._to_hosts[dpid][grp_addr]['servers'][server]['ports']) == 0:
            del self._to_hosts[dpid][grp_addr]['servers'][server]['ports']
            print(self._to_hosts)

        if len(self._to_hosts[dpid][grp_addr]['servers'][server]) == 0:
            print('Remove server')
            del self._to_hosts[dpid][grp_addr]['servers'][server]
            print(self._to_hosts)

        if len(self._to_hosts[dpid][grp_addr]['servers']) == 0:
            print('Not any server')
            del self._to_hosts[dpid][grp_addr]['servers']
            print(self._to_hosts)

        if len(self._to_hosts[dpid][grp_addr]) == 0:
            print('Remove group')
            del self._to_hosts[dpid][grp_addr]
            print(self._to_hosts)

        print("Flow updated")


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
        #print("\n")
        print(msg)
        print(pkt)
        print(igmp_in)
        eth_type = eth.ethertype
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        #self._to_hosts.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if(igmp_in):    #Check if pkt is IGMP control
            #grp_addr = igmp_in.address
            #match = parser.OFPMatch(eth_dst=dst, eth_type=0x0800,ip_proto=17)
            #actions = []
            #server = int(self.serv_to_clt[str(in_port)])
            log = "SW=%s PORT=%d IGMP received. " % (dpid_to_str(dpid), in_port)
            self.logger.debug(str(igmp_in))
            if(igmp_in.msgtype==0x16):
                print("IGMPv2 Report")
                self.logger.info(log + "[REPORT]")
                self.do_report(igmp_in, in_port, msg)

                #if not self._to_hosts[dpid].get(grp_addr):
                #    self._to_hosts[dpid].setdefault(grp_addr, {'servers': {}})
                #    #print(self._to_hosts)
                #    #print("New group")

                #if not self._to_hosts[dpid][grp_addr]['servers'].get(server):
                #    #self._to_hosts[dpid][grp_addr]['servers'].setdefault(server, {'ports': {}})
                #    self._to_hosts[dpid][grp_addr]['servers'][server] = {'ports': {}}
                #    #print(self._to_hosts)
                #    #print("New server")

                #if not self._to_hosts[dpid][grp_addr]['servers'][server]['ports'].get(in_port):
                #    self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port] = {'out': False}
                #    #self._to_hosts[dpid][grp_addr][server]['ports'].setdefault(in_port, {'out': False, 'in': False})
                #    for port in self._to_hosts[dpid][grp_addr]['servers'][server]['ports']:
                #        print(port)
                #        actions.append(parser.OFPActionOutput(port))
                #    match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=server, ipv4_dst=grp_addr)
                #    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                #    #print(self._to_hosts)
                #    #print("New port")

                #if not self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port]['out']:
                #    self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port]['out'] = True
                #    print(self._to_hosts)
                #    print("Flow added")

            elif(igmp_in.msgtype==0x17): 
                print("IGMPv2 Leave Group")
                self.logger.info(log + "[LEAVE]")
                self.do_leave(igmp_in, in_port, msg)
                #print(self._to_hosts)

                #if self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port]['out']:
                #    self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port]['out'] = False
                #    #print(self._to_hosts)
                #    #print("Port by defect")

                #if self._to_hosts[dpid][grp_addr]['servers'][server]['ports'].get(in_port):
                #    print('Remove port')
                #    del self._to_hosts[dpid][grp_addr]['servers'][server]['ports'][in_port]
                #    match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=server, ipv4_dst=grp_addr)
                #    if len(self._to_hosts[dpid][grp_addr]['servers'][server]['ports']) == 0:
                #        self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
                #    else:
                #        for port in self._to_hosts[dpid][grp_addr]['servers'][server]['ports']:
                #            actions.append(parser.OFPActionOutput(port))
                #        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                #    print(self._to_hosts)

                #if len(self._to_hosts[dpid][grp_addr]['servers'][server]['ports']) == 0:
                #    del self._to_hosts[dpid][grp_addr]['servers'][server]['ports']
                #    print(self._to_hosts)

                #if len(self._to_hosts[dpid][grp_addr]['servers'][server]) == 0:
                #    print('Remove server')
                #    del self._to_hosts[dpid][grp_addr]['servers'][server]
                #    print(self._to_hosts)

                #if len(self._to_hosts[dpid][grp_addr]['servers']) == 0:
                #    print('Not any server')
                #    del self._to_hosts[dpid][grp_addr]['servers']
                #    print(self._to_hosts)

                #if len(self._to_hosts[dpid][grp_addr]) == 0:
                #    print('Remove group')
                #    del self._to_hosts[dpid][grp_addr]
                #    print(self._to_hosts)

                #print("Flow updated")

        elif(not igmp_in and dst[:8] == '01:00:5e'):    #Check if pkt is IGMP data
            print("IGMP DATA! No clients")
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
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
