######################################################

######################################
# Application for the global scenario SDN with priorities #
######################################

#Name:        SwitchIGMPv3Priorities

#Description: Application that manages a switch to be a proxy multicast using IGMPv3 
#            to provide multicast traffic from two providers to different clients using 
#            priorities checked in a database

#Author:      Sandra Garcia
######################################################


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
from ryu.lib.packet import igmp
from ryu.lib.packet import ipv4
from collections import defaultdict
from ryu import cfg
import json
import dataset

class SwitchIGMPv3Priorities(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchIGMPv3Priorities, self).__init__(*args, **kwargs) 
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.StrOpt('mac_to_port', default='Not configured', help = ('A string')),
            cfg.StrOpt('to_hosts', default='Not configured', help = ('A string'))])
        mac_to_port = CONF.mac_to_port
        to_hosts = CONF.to_hosts
        self.mac_to_port = json.loads(mac_to_port)
        self._to_hosts = json.loads(to_hosts)

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
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, command=ofproto.OFPFC_DELETE, 
            						out_port=out_port, out_group=ofproto.OFPG_ANY, 
            						priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, command=ofproto.OFPFC_DELETE, 
            						out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, 
            						match=match, instructions=inst)
        datapath.send_msg(mod)

    def do_join(self, in_port, msg, provider, ip_group):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        actions = []

        #To send both messages
        actions = [parser.OFPActionOutput(provider)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)
        actions = []

        if not self._to_hosts[dpid].get(ip_group):
            self._to_hosts[dpid].setdefault(ip_group, {'providers': {}})
        if not self._to_hosts[dpid][ip_group]['providers'].get(provider):
            self._to_hosts[dpid][ip_group]['providers'][provider] = {'ports': {}}
        if not self._to_hosts[dpid][ip_group]['providers'][provider]['ports'].get(in_port):
            self._to_hosts[dpid][ip_group]['providers'][provider]['ports'][in_port] = {'out': False}
            for port in self._to_hosts[dpid][ip_group]['providers'][provider]['ports']:
                actions.append(parser.OFPActionOutput(port))
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=ip_group, in_port=provider)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        if not self._to_hosts[dpid][ip_group]['providers'][provider]['ports'][in_port]['out']:
            self._to_hosts[dpid][ip_group]['providers'][provider]['ports'][in_port]['out'] = True
            print("Flow added")

    def do_leave(self, in_port, msg, provider, ip_group):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        actions = []

        #To send both messages
        actions = [parser.OFPActionOutput(provider)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)
        actions = []

        # It sends 2 Leave messages, the second must be ignored
        if len(self._to_hosts[dpid]) == 0:
            return
        if not self._to_hosts[dpid].get(ip_group):
            return
        if not self._to_hosts[dpid][ip_group]['providers'].get(provider):
            return
        if not self._to_hosts[dpid][ip_group]['providers'][provider]['ports'].get(in_port):
            return

        if self._to_hosts[dpid][ip_group]['providers'][provider]['ports'][in_port]['out']:
            self._to_hosts[dpid][ip_group]['providers'][provider]['ports'][in_port]['out'] = False
        if self._to_hosts[dpid][ip_group]['providers'][provider]['ports'].get(in_port):
            del self._to_hosts[dpid][ip_group]['providers'][provider]['ports'][in_port]
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=ip_group, in_port=provider)
            if len(self._to_hosts[dpid][ip_group]['providers'][provider]['ports']) == 0:
                self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
            else:
                for port in self._to_hosts[dpid][ip_group]['providers'][provider]['ports']:
                    actions.append(parser.OFPActionOutput(port))
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        if len(self._to_hosts[dpid][ip_group]['providers'][provider]['ports']) == 0:
            del self._to_hosts[dpid][ip_group]['providers'][provider]['ports']
        if len(self._to_hosts[dpid][ip_group]['providers'][provider]) == 0:
            del self._to_hosts[dpid][ip_group]['providers'][provider]
        if len(self._to_hosts[dpid][ip_group]['providers']) == 0:
            del self._to_hosts[dpid][ip_group]['providers']
        if len(self._to_hosts[dpid][ip_group]) == 0:
            del self._to_hosts[dpid][ip_group]
        print("Flow updated")

    def get_provider(self, ip_client, ip_group, ip_source):
        self.clients_possible = {}
        self.providers = []
        db = dataset.connect('sqlite:///test.db')
        table_users = db['usersv2']

        #Checks in the db the rows compatible with the condition and takes
        #the one with the highest priority
        result = db['usersv2'].all()
        for res in result:
            if(res['client'] == ip_client or res['client'] == None) and (res['group'] == ip_group or res['group'] == None) and (res['source'] == ip_source or res['source'] == None):
                client = table_users.find_one(id=res['id'])
                provider = client['provider']
                priority = client['priority']
                self.clients_possible.setdefault(priority, []).append(client)

        # With the row chosen, takes the provider value, and does join/leave
        #to that provider (server)
        if self.clients_possible != {}:
            #print('\n')
            max_key = max(self.clients_possible, key=int)
            if len(self.clients_possible[max_key]) > 1:
                for clients_max in self.clients_possible[max_key]:
                    prov = clients_max['provider']
                    self.providers.append(prov)
                return self.providers
            else:
                client_chosen = self.clients_possible[max_key][0]
                provider = client_chosen['provider']
                return provider
        else:
            print('Not allowed - Not registered in the db') 
            return None

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
        ipv4 = pkt.protocols[1]
        udp = pkt.protocols[2]
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        if(igmp_in): #Check if the packet is IGMP
            record = igmp_in.records[0]
            log = "SW=%s PORT=%d IGMP received. " % (dpid_to_str(dpid), in_port)
            if(igmp_in.msgtype==0x22):
                print("IGMPv3 Membership Report")
                #Takes the values from the IGMP message (client, group, source)
                ip_client = ipv4.src
                ip_group = record.address
                ip_source = record.srcs
                if ip_source==[]:   #It can be sent or not
                    ip_source=None
                else:
                    ip_source = record.srcs[0]
                provider_res = self.get_provider(ip_client, ip_group, ip_source) # Returns the provider

                if provider_res != None:
                    if type(provider_res) == int:
                        if((record.srcs==[] and record.type_==4) or (record.srcs!=[] and record.type_==3)):
                            print("IGMPv3 Join")
                            self.logger.info(log + "[Join]")
                            self.do_join(in_port, msg, provider_res, ip_group)
                        elif((record.srcs==[] and record.type_==3) or (record.srcs!=[] and record.type_==6)):
                            print("IGMPv3 Leave")
                            self.logger.info(log + "[Leave]")
                            self.do_leave(in_port, msg, provider_res, ip_group)
                    elif type(provider_res) == list:
                        for provider in provider_res:
                            if((record.srcs==[] and record.type_==4) or (record.srcs!=[] and record.type_==3)):
                                print("IGMPv3 Join")
                                self.logger.info(log + "[Join]")
                                self.do_join(in_port, msg, provider, ip_group)
                            elif((record.srcs==[] and record.type_==3) or (record.srcs!=[] and record.type_==6)):
                                print("IGMPv3 Leave")
                                self.logger.info(log + "[Leave]")
                                self.do_leave(in_port, msg, provider, ip_group)
                    else:
                        print('Not a valid provider')
                else:
                    print('Not registered in the db')   

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
