# Copyright 2014 UnitedStack, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import copy
import traceback

from neutron.agent.linux import ip_lib
from neutron.common import constants as l3_constants
from neutron.common import utils as common_utils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging

LOG = logging.getLogger('uos_l3')

TOP_CHAIN = 'meter-uos'
WRAP_NAME = 'neutron-vpn-agen-'   # this iptable chain name is not proper
FIP_CHAIN_SIZE = 10
TOP_CHAIN_NAME = WRAP_NAME + TOP_CHAIN

class L3AgentMixin(object):

    def _create_ratelimit_qdisc(self, ip_wrapper, ri, interface_name):
        LOG.debug("create ratelimit stuff for device %s", interface_name)
        default_class = 10
        # clear all previous egress qdisc. starts with a clean environment
        tc_cmd = ['tc', 'qdisc', 'del', 'dev', interface_name, 'root']
        ip_wrapper.netns.execute(tc_cmd, check_exit_code=False)
        # attach qdisc to interface
        tc_cmd = ['tc', 'qdisc', 'add', 'dev', interface_name,
                  'root', 'handle', '1:0', 'htb', 'default',
                  '%x' % default_class]
        ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)
        interfaces = [interface_name]
        # need to delete the old ifb from previous
        # version
        ifb0 = self._get_internal_device(interface_name)
        # add egress qdisc for ifb0
        tc_cmd = ['ip', 'link', 'delete', ifb0]
        ip_wrapper.netns.execute(tc_cmd, check_exit_code=False)
        if self.conf.l3_fip_in_qos:
            tc_cmd = ['ip', 'link', 'add', ifb0, 'type', 'ifb']
            ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)
            tc_cmd = ['ip', 'link', 'set', 'dev', ifb0, 'up']
            ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)
            tc_cmd = ['tc', 'qdisc', 'add', 'dev', ifb0,
                      'root', 'handle', '1:', 'htb', 'default',
                      '%x' % default_class]
            ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)

            # add ingress traffic redirect to ifb0
            tc_cmd = ['tc', 'qdisc', 'del', 'dev', interface_name, 'ingress']
            ip_wrapper.netns.execute(tc_cmd, check_exit_code=False)
            tc_cmd = ['tc', 'qdisc', 'add', 'dev', interface_name,
                      'handle', 'ffff:', 'ingress']
            ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)
            tc_cmd = ['tc', 'filter', 'add', 'dev', interface_name,
                      'parent', 'ffff:', 'protocol', 'ip', 'u32',
                      'match', 'u32', '0', '0', 'action', 'mirred',
                      'egress', 'redirect', 'dev', ifb0]
            ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)
            interfaces.append(ifb0)

        # add default class filter and leaf qdisc
        self._add_class_filter(
            ip_wrapper, default_class, interfaces, 1024)
        ri.fip_class_ratelimit_dict = {}
        ri.available_classes = set(xrange(11, 65530))

    def _delete_ratelimit_qdisc(self, ip_wrapper, interface_name):
        """Is called after qg-xxx is unpluged."""
        if not self.conf.l3_fip_in_qos:
            return
        ifb = self._get_internal_device(interface_name)
        tc_cmd = ['ip', 'link', 'delete', ifb]
        ip_wrapper.netns.execute(tc_cmd, check_exit_code=False)

    def process_rate_limit(self, ri, external_interface):
        interfaces = [external_interface]
        if self.conf.l3_fip_in_qos:
            _interface = self._get_internal_device(external_interface)
            interfaces.append(_interface)
        available_fips = set()
        ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      namespace=ri.ns_name)
        if LOG.logger.isEnabledFor(10):
            LOG.debug("process_rate_limit before fip class map %s",
                      jsonutils.dumps(ri.fip_class_ratelimit_dict,
                                      indent=5))
        fips = []
        for fip in ri.router.get(l3_constants.FLOATINGIP_KEY, []):
            fips.append({'floating_ip_address':
                         fip['floating_ip_address'],
                         'rate_limit': fip['rate_limit'],
                         'id': fip['id']})
        for fip in ri.router.get(l3_constants.UOS_GW_FIP_KEY, []):
            fips.append({'floating_ip_address':
                         fip['floating_ip_address'],
                         'rate_limit': fip['rate_limit'],
                         'id': fip['id']})
        gw_port = ri.router.get('gw_port')
        if gw_port:
            rate_limit = gw_port.get('rate_limit', 0)
            if rate_limit > 0:
                fip_id = gw_port['device_id']
                fip_ip = gw_port['fixed_ips'][0]['ip_address']
                fips.append({'floating_ip_address': fip_ip,
                             'rate_limit': rate_limit,
                             'id': fip_id})
        for fip in fips:
            LOG.debug("FIP process_rate_limit %s", fip)
            fip_ip = fip['floating_ip_address']
            rate_limit = fip.get('rate_limit', 0)
            if rate_limit > 0:
                available_fips.add(fip['id'])
                if not ri.available_classes:
                    LOG.error(
                        _("No class id available for floatingip-id=%s"),
                        fip['id'])
                    return
                class_rate = ri.fip_class_ratelimit_dict.get(fip['id'], {})
                if not class_rate:
                    class_rate['minor_id'] = ri.available_classes.pop()
                ri.fip_class_ratelimit_dict[fip['id']] = class_rate
                minor_id = class_rate['minor_id']
                old_rate_limit = class_rate.get('rate_limit', 0)
                if (old_rate_limit != rate_limit):
                    self._add_class_filter(ip_wrapper, minor_id,
                                           interfaces,
                                           rate_limit, fip_ip=fip_ip)
                    class_rate['rate_limit'] = rate_limit
                    class_rate['fip_ip'] = fip_ip
        deleted_ips = set(ri.fip_class_ratelimit_dict.keys()) - available_fips
        LOG.debug("Deleted fixed ips %s", deleted_ips)
        for fip_id in deleted_ips:
            class_rate = ri.fip_class_ratelimit_dict[fip_id]
            self._delete_class_filter(
                ip_wrapper, class_rate['minor_id'],
                interfaces, class_rate['fip_ip'])
            ri.fip_class_ratelimit_dict.pop(fip_id, None)
            ri.available_classes.add(class_rate['minor_id'])
        if LOG.logger.isEnabledFor(10):
            LOG.debug("process_rate_limit end fip class map %s",
                      jsonutils.dumps(ri.fip_class_ratelimit_dict,
                                      indent=5))

    def _delete_class_filter(self, ip_wrapper, minor_id, devs,
                             fip_ip):
        for _int_name in devs:
            # we must delete filter first
            # delete filters (filtering by fwmark)
            tc_cmd = self._get_delete_filter_cmd(
                _int_name, fip_ip, minor_id)
            ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)
            # and then classes, which will delete the leaf qdisc
            tc_cmd = ['tc', 'class', 'delete', 'dev', _int_name,
                      'parent', '1:', 'classid', '1:%x' % minor_id]
            ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)

    def _add_class_filter(self, ip_wrapper, minor_id, devs,
                          rate_limit, fip_ip=None):
        for _int_name in devs:
            if not _int_name:
                continue
            burst = str(int(rate_limit) / 100)
            # add classes according to rate limit
            tc_cmd = ['tc', 'class', 'replace', 'dev', _int_name,
                      'parent', '1:', 'classid',
                      '1:%x' % minor_id, 'htb',
                      'rate', '%skbit' % rate_limit, 'ceil',
                      '%skbit' % rate_limit,
                      'burst', '%sk' % burst, 'cburst',
                      '%sk' % burst, 'prio', '10']
            ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)
            # add leaf sfq qdisc according
            tc_cmd = ['tc', 'qdisc', 'replace', 'dev', _int_name,
                      'parent', '1:%x' % minor_id, 'handle',
                      '%x:' % minor_id, 'sfq']
            ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)
            if fip_ip:
                tc_cmd = self._get_replace_filter_cmd(
                    _int_name, fip_ip, minor_id)
                ip_wrapper.netns.execute(tc_cmd, check_exit_code=True)

    def _get_replace_filter_cmd(self, interface, addr, minor):
        srcflag = interface.startswith("qg-")
        # we use different prio so that we can delete it via prio
        tccmd = ("tc filter replace dev %(interface)s parent 1: protocol "
                 "ip prio %(minor)d u32 match ip %(src_dst)s %(addr)s/32 "
                 "flowid 1:%(minor)x") % {"interface": interface,
                                   "src_dst": (srcflag and "src" or "dst"),
                                   "addr": addr,
                                   "minor": minor}
        LOG.debug("_get_replace_filter_cmd: %s", tccmd)
        return tccmd.split()

    def _get_delete_filter_cmd(self, interface, addr, minor):
        tccmd = ("tc filter delete dev %(interface)s parent 1: protocol "
                 "ip prio %(minor)d") % {"interface": interface,
                                         "minor": minor}
        LOG.debug("_get_delete_filter_cmd: %s", tccmd)
        return tccmd.split()

    def _get_internal_device(self, external_interface):
        return 'ifb' + external_interface.split("qg-", 1)[1]

    def get_qg_device_name(self, ri):
        # 14 is the length of qg device in router
        gw_port_id = ri.router.get('gw_port_id', None)
        if gw_port_id:
            return ('qg-' + ri.router['gw_port_id'])[:14]
        LOG.debug('This router %s does not have gw_port' % ri.router)
        return None

    def create_top_chain(self, ip_wrapper, ri):
        #create a top chain named 'neutron-vpn-agen-meter-uos'
        #and append it to  neutron-vpn-agen-FORWARD
        cmd = '-j ' + '$' + TOP_CHAIN
        ri.iptables_manager.ipv4['filter'].add_chain(TOP_CHAIN)
        ri.iptables_manager.ipv4['filter'].add_rule('FORWARD', cmd)

    def create_fip_chain_and_rule(self, ip_wrapper, ri, fip, qg_dev):
        #generate rule for floatingip
        fip_chain_name = fip['id'][:FIP_CHAIN_SIZE]
        fixed_ip = fip['fixed_ip'] + '/32'

        cmd = '-j ' + '$' + fip_chain_name
        ri.iptables_manager.ipv4['filter'].add_chain(fip_chain_name)
        ri.iptables_manager.ipv4['filter'].add_rule(TOP_CHAIN, cmd)

        if fip['flag'] == l3_constants.UOS_GW_FIP_KEY:
            #egress rule
            o_rule_cmd = '-o ' + qg_dev
            i_rule_cmd = '-i ' + qg_dev
            ri.iptables_manager.ipv4['filter'].add_rule(fip_chain_name, o_rule_cmd)
            ri.iptables_manager.ipv4['filter'].add_rule(fip_chain_name, i_rule_cmd)

        elif fip['flag'] == l3_constants.FLOATINGIP_KEY:
            #egress rule
            o_rule_cmd = '-s ' + fixed_ip + ' -o ' + qg_dev
            i_rule_cmd = '-d ' + fixed_ip + ' -i ' + qg_dev
            ri.iptables_manager.ipv4['filter'].add_rule(fip_chain_name, o_rule_cmd)
            ri.iptables_manager.ipv4['filter'].add_rule(fip_chain_name, i_rule_cmd)


    def get_fip_traffic(self, ip_wrapper, fip_id, ri):
        #get one floatingip traffic
        cmd = ['iptables', '-t', 'filter', '-L', WRAP_NAME + fip_id[:FIP_CHAIN_SIZE], '-n', '-v', '-x']
        acc = {}

        try:
            result = ip_wrapper.netns.execute(cmd, check_exit_code=True)
        except:
            LOG.warning("Chain %s not found!" % fip_id[:FIP_CHAIN_SIZE])
            return acc

        data = result.split('\n')[2:]

        if len(data) > 1:
            acc['fip_network_out'] = {'pkts': data[0].split()[0], 'bytes':data[0].split()[1]}
            acc['fip_network_in'] = {'pkts': data[1].split()[0], 'bytes':data[1].split()[1]}
            acc['fip_id'] = fip_id
            acc['tenant_id'] = ri.all_fips[fip_id]['tenant_id']

            # get all vms floatingips(in and out) pkts and bytes
            ri.all_fips['vm_fip_out']['pkts'] += int(data[0].split()[0])
            ri.all_fips['vm_fip_out']['bytes'] += int(data[0].split()[1])
            ri.all_fips['vm_fip_in']['pkts'] += int(data[1].split()[0])
            ri.all_fips['vm_fip_in']['bytes'] += int(data[1].split()[1])

        return acc

    def get_router_fip_traffic(self, ip_wrapper, fip_id, ri):

        cmd = ['iptables', '-t', 'filter', '-L', WRAP_NAME + fip_id[:FIP_CHAIN_SIZE], '-n', '-v', '-x']
        acc = {}
        acc['fip_network_in'] = {}
        acc['fip_network_out'] = {}

        try:
            result = ip_wrapper.netns.execute(cmd, check_exit_code=True)
        except RuntimeError:
            LOG.warning("Chain %s not found!" % fip_id[:FIP_CHAIN_SIZE])
            return acc

        data = result.split('\n')[2:]

        if len(data) > 2:

            # get router floatingip(in and out) pkts and bytes
            acc['fip_network_out']['pkts'] = (
                int(data[0].split()[0]) - ri.all_fips['vm_fip_out']['pkts'])
            acc['fip_network_out']['bytes'] = (
                int(data[0].split()[1]) - ri.all_fips['vm_fip_out']['bytes'])
            acc['fip_network_in']['pkts'] = (
                int(data[1].split()[0]) - ri.all_fips['vm_fip_in']['pkts'])
            acc['fip_network_in']['bytes'] = (
                int(data[1].split()[1]) - ri.all_fips['vm_fip_in']['bytes'])

            acc['fip_id'] = fip_id
            acc['tenant_id'] = ri.all_fips[fip_id]['tenant_id']

        return acc

    def get_all_fips_traffic(self, ris):
        # get all floatingips traffic
        fip_traffic_list = []

        for ri in ris:

            # init ri.all_fips's ingress and egress pkts & bytes
            # ri.all_fips store all vm's floatingip pkts and bytes
            ri.all_fips['vm_fip_in'] = {'pkts': 0, 'bytes': 0}
            ri.all_fips['vm_fip_out'] = {'pkts': 0, 'bytes': 0}

            ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                          namespace=ri.ns_name)

            #lock! other threading please wait!
            if ri.lock.acquire():
                copy_ri_fip = copy.copy(ri.fip_metering_set)
                ri.lock.release()
                #unlock!

            for fip_id in copy_ri_fip:

                if fip_id != ri.uos_gateway_fip:
                    data = self.get_fip_traffic(ip_wrapper, fip_id, ri)
                    if data:
                        fip_traffic_list.append(data)

                if fip_id == ri.uos_gateway_fip:
                    data = self.get_router_fip_traffic(ip_wrapper, ri.uos_gateway_fip, ri)
                    if data:
                        fip_traffic_list.append(data)

        return fip_traffic_list

    def process_metering_label(self, ri):

        qg_dev = self.get_qg_device_name(ri)
        ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      namespace=ri.ns_name)

        #check the router if has top chain
        is_metering = ri.iptables_manager.ipv4['filter'].is_chain_empty(TOP_CHAIN)

        if not is_metering:
            #not metering, so create a top chain
            self.create_top_chain(ip_wrapper, ri)

        fips = []
        available_fips_set = set()

        LOG.info('router %s get fips from server', ri.router_id)
        #sync all fips from server
        for fip in ri.router.get(l3_constants.FLOATINGIP_KEY, []):
            fips.append({'floating_ip_address':
                         fip['floating_ip_address'],
                         'fixed_ip':fip['fixed_ip_address'],
                         'id':fip['id'], 'flag':l3_constants.FLOATINGIP_KEY})

            #add fix_ip into ri
            ri.all_fips[fip['id']] = {'fixed_ip': None, 'tenant_id': None}
            ri.all_fips[fip['id']]['fixed_ip'] = fip['fixed_ip_address']
            ri.all_fips[fip['id']]['tenant_id'] = fip['tenant_id']

        LOG.info(' router %s get fips from server end', ri.router_id)
        for fip in ri.router.get(l3_constants.UOS_GW_FIP_KEY, []):
            fips.append({'floating_ip_address':
                         fip['floating_ip_address'],
                         'fixed_ip':fip['fixed_ip_address'],
                         'id':fip['id'], 'flag':l3_constants.UOS_GW_FIP_KEY})

            #add fix_ip into ri
            ri.all_fips[fip['id']] = {'fixed_ip': None, 'tenant_id': None}
            ri.all_fips[fip['id']]['fixed_ip'] = fip['fixed_ip_address']
            ri.all_fips[fip['id']]['tenant_id'] = fip['tenant_id']

            ri.uos_gateway_fip = fip['id']

        LOG.info(' router %s get uos fip end', ri.router_id)
        LOG.debug('Sync fips from server are %s' % fips)

        try:
            wait_add_fips = set()
            for fip in fips:
                wait_add_fips.add(fip['id'])
                #get fip chain_name
                fip_chain_name = fip['id'][:FIP_CHAIN_SIZE]

                #check the fip_chain if exists
                fip_is_metering = ri.iptables_manager.ipv4['filter'].is_chain_empty(fip_chain_name)

                #sync all floatingips and store in available_fips
                available_fips_set.add(fip['id'])

                if not fip_is_metering:#not exist, so generate iptables rule
                    self.create_fip_chain_and_rule(ip_wrapper, ri, fip, qg_dev)

            LOG.info(' router %s manage fips done', ri.router_id)
            # lock! other threadings please wait!
            if ri.lock.acquire():
                #update ri fip_metering_fips
                ri.fip_metering_set = ri.fip_metering_set | wait_add_fips
                deleted_fips = ri.fip_metering_set - available_fips_set
                ri.fip_metering_set = ri.fip_metering_set - deleted_fips
                ri.lock.release()
                #unlock!
            LOG.info(' router %s lock release', ri.router_id)

            LOG.debug("Deleted floatingips are %s", deleted_fips)
            for fip_id in deleted_fips:
                #remove chain and chain's rules
                remove_chain_name = fip_id[:FIP_CHAIN_SIZE]
                ri.iptables_manager.ipv4['filter'].remove_chain(remove_chain_name)

                #remove fip from all_fips
                ri.all_fips.pop(fip_id, None)

                if ri.uos_gateway_fip == fip_id:
                    ri.uos_gateway_fip = None
            LOG.info(' router %s metering end', ri.router_id)

        except Exception:
            LOG.error("error happen in process_metering start")
            LOG.error(traceback.format_exc())
            LOG.error("error happen in process_metering end")
