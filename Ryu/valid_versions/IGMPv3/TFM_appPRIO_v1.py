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
import dataset


class SimpleSwitchIGMP13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {'igmplib': igmplib.IgmpLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchIGMP13, self).__init__(*args, **kwargs)
        #self._snoop = kwargs['igmplib']
        
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.StrOpt('mac_to_port', default='Not configured', help = ('A string')),
            cfg.StrOpt('to_hosts', default='Not configured', help = ('A string')),
            cfg.StrOpt('server_ip_to_port', default='Not configured', help = ('A string')),
            cfg.StrOpt('server_to_client', default='Not configured', help = ('A string'))])
        mac_to_port = CONF.mac_to_port
        to_hosts = CONF.to_hosts
        server_ip_to_port = CONF.server_ip_to_port
        server_to_client = CONF.server_to_client 
       
        self.serv_to_clt = json.loads(server_to_client) #Convert from str to dict
        self.mac_to_port = json.loads(mac_to_port)
        self._to_hosts = json.loads(to_hosts)
        self.serv_ip_to_port = json.loads(server_ip_to_port)

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

    def do_join(self, in_port, msg, provider, ip_group):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        actions = []
        #server = int(self.serv_to_clt[str(in_port)])
        server_port = int(self.serv_ip_to_port[provider])

        #To send both messages
        actions = [parser.OFPActionOutput(server_port)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)

        actions = []

        if not self._to_hosts[dpid].get(ip_group):
            self._to_hosts[dpid].setdefault(ip_group, {'servers': {}})

        if not self._to_hosts[dpid][ip_group]['servers'].get(provider):
            self._to_hosts[dpid][ip_group]['servers'][provider] = {'ports': {}}

        if not self._to_hosts[dpid][ip_group]['servers'][provider]['ports'].get(in_port):
            self._to_hosts[dpid][ip_group]['servers'][provider]['ports'][in_port] = {'out': False}
            for port in self._to_hosts[dpid][ip_group]['servers'][provider]['ports']:
                actions.append(parser.OFPActionOutput(port))
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=ip_group, ipv4_src=provider)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        if not self._to_hosts[dpid][ip_group]['servers'][provider]['ports'][in_port]['out']:
            self._to_hosts[dpid][ip_group]['servers'][provider]['ports'][in_port]['out'] = True
            print(self._to_hosts)
            print("Flow added")

    def do_leave(self, in_port, msg, provider, ip_group):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        actions = []
        server_port = int(self.serv_ip_to_port[provider])

        #To send both messages
        actions = [parser.OFPActionOutput(server_port)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)

        actions = []

        # It sends 2 Leave messages, the second must be ignored
        if len(self._to_hosts[dpid]) == 0:
            return
        if not self._to_hosts[dpid].get(ip_group):
            return
        if not self._to_hosts[dpid][ip_group]['servers'].get(provider):
            return
        if not self._to_hosts[dpid][ip_group]['servers'][provider]['ports'].get(in_port):
            return

        if self._to_hosts[dpid][ip_group]['servers'][provider]['ports'][in_port]['out']:
            self._to_hosts[dpid][ip_group]['servers'][provider]['ports'][in_port]['out'] = False

        if self._to_hosts[dpid][ip_group]['servers'][provider]['ports'].get(in_port):
            #print('Remove port')
            del self._to_hosts[dpid][ip_group]['servers'][provider]['ports'][in_port]
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=ip_group, ipv4_src=provider)
            if len(self._to_hosts[dpid][ip_group]['servers'][provider]['ports']) == 0:
                self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
            else:
                for port in self._to_hosts[dpid][ip_group]['servers'][provider]['ports']:
                    actions.append(parser.OFPActionOutput(port))
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        if len(self._to_hosts[dpid][ip_group]['servers'][provider]['ports']) == 0:
            del self._to_hosts[dpid][ip_group]['servers'][provider]['ports']

        if len(self._to_hosts[dpid][ip_group]['servers'][provider]) == 0:
            del self._to_hosts[dpid][ip_group]['servers'][provider]

        if len(self._to_hosts[dpid][ip_group]['servers']) == 0:
            del self._to_hosts[dpid][ip_group]['servers']

        if len(self._to_hosts[dpid][ip_group]) == 0:
            del self._to_hosts[dpid][ip_group]
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
        ipv4 = pkt.protocols[1]
        udp = pkt.protocols[2]
        #print(pkt)
        eth_type = eth.ethertype
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        # Connects to the db (already created in another script, has the configuration done)
        db = dataset.connect('sqlite:///test.db')
        table_users = db['users']
        #print(db['users'].columns)
        
        if(igmp_in):    #Check if pkt is IGMP control
            record = igmp_in.records[0]
            log = "SW=%s PORT=%d IGMP received. " % (dpid_to_str(dpid), in_port)

            #Dict for the possible rows that accomplish the if condition
            self.clients_possible = {}
            #self.logger.debug(str(igmp_in))
            if(igmp_in.msgtype==0x22):
                print("IGMPv3 Membership Report")
                #Takes the values from the IGMP message (client, group, source)
                ip_client = ipv4.src
                ip_group = record.address
                ip_source = record.srcs
                if ip_source==[]:   #It can be sent or not in the client
                    ip_source=None
                else:
                    ip_source = record.srcs[0]

                #Checks in the db the rows compatible with the condition and takes
                #the one with the highest priority
                result = db['users'].all()
                for res in result:
                   if(res['client'] == ip_client or res['client'] == None) and (res['group'] == ip_group or res['group'] == None) and (res['source'] == ip_source or res['source'] == None):
                        print(res['id'])
                        client = table_users.find_one(id=res['id'])
                        print(client)
                        provider = client['provider']
                        priority = client['priority']
                        if priority not in self.clients_possible:
                            self.clients_possible.setdefault(priority, []).append(client)
                        else:
                            break
                print(self.clients_possible)
                
                # With the row chosen, takes the provider value, and does join/leave
                #to that provider (server)
                if self.clients_possible != {}:
                    print('\n')
                    max_key = max(self.clients_possible, key=int)
                    print(max_key)
                    client_chosen = self.clients_possible[max_key][0]
                    provider = client_chosen['provider']
                    print(provider) 

                    if((record.srcs==[] and record.type_==4) or (record.srcs!=[] and record.type_==3)):
                        print("IGMPv3 Join")
                        self.logger.info(log + "[Join]")
                        self.do_join(in_port, msg, provider, ip_group)
                    elif((record.srcs==[] and record.type_==3) or (record.srcs!=[] and record.type_==6)):
                        print("IGMPv3 Leave")
                        self.logger.info(log + "[Leave]")
                        self.do_leave(in_port, msg, provider, ip_group)
                else:
                    print('Not allowed - Not registered in the db')            

        elif(udp and dst[:8] == '01:00:5e'): #Is empty, shouldn't send
            print("Nobody's listening")

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
