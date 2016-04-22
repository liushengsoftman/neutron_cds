# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 UnitedStack, Inc.
# All rights reserved.
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
# @author: liusheng ,CDS
#
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.extensions import floatingip_ratelimits as ratelimits
from neutron.extensions import l3
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


# this class will be called in function:_make_floatingip_dict()
class FloatingIPRateLimitsDbMixin(l3_db.L3_NAT_db_mixin):

    def _extend_floatingip_dict_ratelimit(self, res, db):
        res[ratelimits.RATE_LIMIT] = db.rate_limit

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.FLOATINGIPS, ['_extend_floatingip_dict_ratelimit'])
