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


######################################################################

#To configure mode: ryu-manager app.py --config-file file.conf

######################################################################

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
from ryu.lib.packet import ipv4
#from ryu.lib import igmplib
from collections import defaultdict
from ryu import cfg
import json
from ast import literal_eval

class SimpleSwitchIGMP13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {'igmplib': igmplib.IgmpLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchIGMP13, self).__init__(*args, **kwargs)
        #self._snoop = kwargs['igmplib']
        #self.mac_to_port = {}
        #self._to_hosts = {}
        #self.serv_to_clt = {'1': '5', '2': '5', '3': '6', '4': '6'}
        #self.serv_ip_to_port = {'10.100.0.21': '5', '10.100.0.22': '6'}
        #self.tupla = {'10.100.0.21': ('None', '224.0.122.5', '10.100.0.21')}
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.StrOpt('mac_to_port', default='Not configured', help = ('A string')),
            cfg.StrOpt('to_hosts', default='Not configured', help = ('A string')),
            cfg.StrOpt('server_ip_to_port', default='Not configured', help = ('A string')),
            cfg.StrOpt('server_to_client', default='Not configured', help = ('A string'))])
            #cfg.StrOpt('tupla', default='Not configured', help = ('A list'))])
        mac_to_port = CONF.mac_to_port
        to_hosts = CONF.to_hosts
        server_ip_to_port = CONF.server_ip_to_port
        server_to_client = CONF.server_to_client 
        #tupla = CONF.tupla
        self.serv_to_clt = json.loads(server_to_client) #Convert from str to dict
        self.mac_to_port = json.loads(mac_to_port)
        self._to_hosts = json.loads(to_hosts)
        self.serv_ip_to_port = json.loads(server_ip_to_port)
        #self.tupla = literal_eval(tupla)

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

    #def do_join_SSM(self, igmp_in, in_port, msg, provider):
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
            print(self._to_hosts)
            print("Flow added")

    def do_join_ASM(self, igmp_in, in_port, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        record = igmp_in.records[0]
        grp_addr = record.address
        actions = []

        #To send both messages
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)

        if not self._to_hosts[dpid].get(grp_addr):
            self._to_hosts[dpid].setdefault(grp_addr, {'ports': {}})

        if not self._to_hosts[dpid][grp_addr]['ports'].get(in_port):
            self._to_hosts[dpid][grp_addr]['ports'][in_port] = {'out': False}
            for port in self._to_hosts[dpid][grp_addr]['ports']:
                actions.append(parser.OFPActionOutput(port))
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        if not self._to_hosts[dpid][grp_addr]['ports'][in_port]['out']:
            self._to_hosts[dpid][grp_addr]['ports'][in_port]['out'] = True
            print(self._to_hosts)
            print("Flow added")

    def do_join_client(self, igmp_in, in_port, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        actions = []
        server = int(self.serv_to_clt[str(in_port)])

        #To send both messages
        actions = [parser.OFPActionOutput(server)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)

        if not self._to_hosts[dpid]:
            self._to_hosts[dpid] = {'servers': {}}

        if not self._to_hosts[dpid]['servers'].get(server):
            self._to_hosts[dpid]['servers'][server] = {'ports': {}}

        if not self._to_hosts[dpid]['servers'][server]['ports'].get(in_port):
            self._to_hosts[dpid]['servers'][server]['ports'][in_port] = {'out': False}
            for port in self._to_hosts[dpid]['servers'][server]['ports']:
                actions.append(parser.OFPActionOutput(port))
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=server)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        if not self._to_hosts[dpid]['servers'][server]['ports'][in_port]['out']:
            self._to_hosts[dpid]['servers'][server]['ports'][in_port]['out'] = True
            print(self._to_hosts)
            print("Flow added")

    def do_join_source(self, igmp_in, in_port, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        record = igmp_in.records[0]
        actions = []
        server_ip = record.srcs[0]
        server_port = int(self.serv_ip_to_port[server_ip])

        #To send both messages
        actions = [parser.OFPActionOutput(server_port)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)

        if not self._to_hosts[dpid]:
            self._to_hosts[dpid] = {'servers': {}}

        if not self._to_hosts[dpid]['servers'].get(server_ip):
            self._to_hosts[dpid]['servers'][server_ip] = {'ports': {}}

        if not self._to_hosts[dpid]['servers'][server_ip]['ports'].get(in_port):
            self._to_hosts[dpid]['servers'][server_ip]['ports'][in_port] = {'out': False}
            for port in self._to_hosts[dpid]['servers'][server_ip]['ports']:
                actions.append(parser.OFPActionOutput(port))
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_src=server_ip)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        if not self._to_hosts[dpid]['servers'][server_ip]['ports'][in_port]['out']:
            self._to_hosts[dpid]['servers'][server_ip]['ports'][in_port]['out'] = True
            print(self._to_hosts)
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
            #print('Remove port')
            del self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports'][in_port]
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr, ipv4_src=server_ip)
            if len(self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports']) == 0:
                self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
            else:
                for port in self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports']:
                    actions.append(parser.OFPActionOutput(port))
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            #print(self._to_hosts)

        if len(self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports']) == 0:
            del self._to_hosts[dpid][grp_addr]['servers'][server_ip]['ports']
            #print(self._to_hosts)

        if len(self._to_hosts[dpid][grp_addr]['servers'][server_ip]) == 0:
            #print('Remove server')
            del self._to_hosts[dpid][grp_addr]['servers'][server_ip]
            #print(self._to_hosts)

        if len(self._to_hosts[dpid][grp_addr]['servers']) == 0:
            #print('Not any server')
            del self._to_hosts[dpid][grp_addr]['servers']
            #print(self._to_hosts)

        if len(self._to_hosts[dpid][grp_addr]) == 0:
            #print('Remove group')
            del self._to_hosts[dpid][grp_addr]
            #print(self._to_hosts)
        print("Flow updated")

    def do_leave_ASM(self, igmp_in, in_port, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        record = igmp_in.records[0]
        grp_addr = record.address
        actions = []

        #To send both messages
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)

        actions = []

        # It sends 2 Leave messages, the second must be ignored
        if len(self._to_hosts[dpid]) == 0:
            return
        if not self._to_hosts[dpid].get(grp_addr):
            return
        if not self._to_hosts[dpid][grp_addr]['ports'].get(in_port):
            return

        if self._to_hosts[dpid][grp_addr]['ports'][in_port]['out']:
            self._to_hosts[dpid][grp_addr]['ports'][in_port]['out'] = False

        if self._to_hosts[dpid][grp_addr]['ports'].get(in_port):
            #print('Remove port')
            del self._to_hosts[dpid][grp_addr]['ports'][in_port]
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=grp_addr)
            if len(self._to_hosts[dpid][grp_addr]['ports']) == 0:
                self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
            else:
                for port in self._to_hosts[dpid][grp_addr]['ports']:
                    actions.append(parser.OFPActionOutput(port))
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            #print(self._to_hosts)

        if len(self._to_hosts[dpid][grp_addr]['ports']) == 0:
            del self._to_hosts[dpid][grp_addr]['ports']
            #print(self._to_hosts)

        if len(self._to_hosts[dpid][grp_addr]) == 0:
            #print('Remove group')
            del self._to_hosts[dpid][grp_addr]
            #print(self._to_hosts)
        print("Flow updated")

    def do_leave_client(self, igmp_in, in_port, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        actions = []
        server = int(self.serv_to_clt[str(in_port)])

        #To send both messages
        actions = [parser.OFPActionOutput(server)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)

        actions = []

        # It sends 2 Leave messages, the second must be ignored
        if len(self._to_hosts[dpid]) == 0:
            return
        if not self._to_hosts[dpid]['servers'].get(server):
            return
        if not self._to_hosts[dpid]['servers'][server]['ports'].get(in_port):
            return

        if self._to_hosts[dpid]['servers'][server]['ports'][in_port]['out']:
            self._to_hosts[dpid]['servers'][server]['ports'][in_port]['out'] = False

        if self._to_hosts[dpid]['servers'][server]['ports'].get(in_port):
            #print('Remove port')
            del self._to_hosts[dpid]['servers'][server]['ports'][in_port]
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, in_port=server)
            if len(self._to_hosts[dpid]['servers'][server]['ports']) == 0:
                self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
            else:
                for port in self._to_hosts[dpid]['servers'][server]['ports']:
                    actions.append(parser.OFPActionOutput(port))
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            #print(self._to_hosts)

        if len(self._to_hosts[dpid]['servers'][server]['ports']) == 0:
            del self._to_hosts[dpid]['servers'][server]['ports']
            #print(self._to_hosts)

        if len(self._to_hosts[dpid]['servers'][server]) == 0:
            #print('Remove server')
            del self._to_hosts[dpid]['servers'][server]
            #print(self._to_hosts)

        if len(self._to_hosts[dpid]['servers']) == 0:
            #print('Not any server')
            del self._to_hosts[dpid]['servers']
            #print(self._to_hosts)
        print("Flow updated")

    def do_leave_source(self, igmp_in, in_port, msg): 
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        actions = []
        record = igmp_in.records[0]
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
        if not self._to_hosts[dpid]['servers'].get(server_ip):
            return
        if not self._to_hosts[dpid]['servers'][server_ip]['ports'].get(in_port):
            return

        if self._to_hosts[dpid]['servers'][server_ip]['ports'][in_port]['out']:
            self._to_hosts[dpid]['servers'][server_ip]['ports'][in_port]['out'] = False

        if self._to_hosts[dpid]['servers'][server_ip]['ports'].get(in_port):
            #print('Remove port')
            del self._to_hosts[dpid]['servers'][server_ip]['ports'][in_port]
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_src=server_ip)
            if len(self._to_hosts[dpid]['servers'][server_ip]['ports']) == 0:
                self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
            else:
                for port in self._to_hosts[dpid]['servers'][server_ip]['ports']:
                    actions.append(parser.OFPActionOutput(port))
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            #print(self._to_hosts)            

        if len(self._to_hosts[dpid]['servers'][server_ip]['ports']) == 0:
            del self._to_hosts[dpid]['servers'][server_ip]['ports']
            #print(self._to_hosts)

        if len(self._to_hosts[dpid]['servers'][server_ip]) == 0:
            #print('Remove server')
            del self._to_hosts[dpid]['servers'][server_ip]
            #print(self._to_hosts)

        if len(self._to_hosts[dpid]['servers']) == 0:
            #print('Not any server')
            del self._to_hosts[dpid]['servers']
            #print(self._to_hosts)
        print("Flow updated")

    #def obtain_provider(self, tupla, client, group, source):
    #    provider = list(tupla.keys())[list(tupla.values()).index((client,group,source))]
    #    #print(provider)
    #    return provider

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
        ipv4 = pkt.protocols[1]
        udp = pkt.protocols[2]
    
        eth_type = eth.ethertype
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        #Config parameters
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.StrOpt('mode_SSM', default='Not configured', help = ('A string')), # If not configured, default 
            cfg.StrOpt('mode_ASM', default='Not configured', help = ('A string')),
            cfg.StrOpt('mode_Client', default='Not configured', help = ('A string')),
            cfg.StrOpt('mode_Source', default='Not configured', help = ('A string'))]) 
        print(CONF.mode_SSM)
        print(CONF.mode_ASM)
        print(CONF.mode_Client)
        print(CONF.mode_Source)

        if(igmp_in):    #Check if pkt is IGMP control
            record = igmp_in.records[0]
            log = "SW=%s PORT=%d IGMP received. " % (dpid_to_str(dpid), in_port)
            #self.logger.debug(str(igmp_in))
            if(igmp_in.msgtype==0x22):
                print("IGMPv3 Membership Report")
                if(record.srcs==[] and record.type_==4 and CONF.mode_ASM=="ASM"):
                    print("IGMPv3 Join Group ASM")
                    self.logger.info(log + "[Join ASM]")
                    self.do_join_ASM(igmp_in, in_port, msg)
                elif(record.srcs==[] and record.type_==3 and CONF.mode_ASM=="ASM"):
                    print("IGMPv3 Leave Group ASM")
                    self.logger.info(log + "[Leave ASM]")
                    self.do_leave_ASM(igmp_in, in_port, msg)
                elif(record.srcs!=[] and record.type_==3 and CONF.mode_SSM=="SSM"):
                    print("IGMPv3 Join Group SSM")
                    self.logger.info(log + "[Join SSM]")
                    #client = 'None'
                    #record = igmp_in.records[0]
                    #group = record.address
                    #source = record.srcs[0]
                    #tupla = self.tupla
                    #provider = self.obtain_provider(tupla, client, group, source)
                    #print(provider)
                    #self.do_join_SSM(igmp_in, in_port, msg, provider)
                    self.do_join_SSM(igmp_in, in_port, msg)
                elif(record.srcs!=[] and record.type_==6 and CONF.mode_SSM=="SSM"):
                    print("IGMPv3 Leave Group SSM")
                    self.logger.info(log + "[Leave SSM]")
                    self.do_leave_SSM(igmp_in, in_port, msg)
                #--------- Solo miras C y obtienes proveedor P (dicc) -------
                elif(record.srcs==[] and record.type_==4 and CONF.mode_Client=="Client"):
                    print("IGMPv3 Join (C, *)")
                    self.logger.info(log + "[Join from client]")
                    self.do_join_client(igmp_in, in_port, msg)
                elif(record.srcs==[] and record.type_==3 and CONF.mode_Client=="Client"):
                    print("IGMPv3 Leave (C, *)")
                    self.logger.info(log + "[Leave from client]")
                    self.do_leave_client(igmp_in, in_port, msg)
                #--------- Solo miras S y obtienes proveedor P (dicc) -------
                elif(record.srcs!=[] and record.type_==3 and CONF.mode_Source=="Source"):
                    print("IGMPv3 Join (S, *)")
                    self.logger.info(log + "[Join from source]")
                    self.do_join_source(igmp_in, in_port, msg)
                elif(record.srcs!=[] and record.type_==6 and CONF.mode_Source=="Source"):
                    print("IGMPv3 Leave (S, *)")
                    self.logger.info(log + "[Leave from source]")
                    self.do_leave_source(igmp_in, in_port, msg)
                else:
                    print("Choose a correct configuration")

        elif(udp and dst[:8] == '01:00:5e'): #Is empty, shouldn't send
            print("Nobody's listening")

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
