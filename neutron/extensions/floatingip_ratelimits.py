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
# @author: liusheng, CDS Technology co.LTD
#

from oslo.config import cfg

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as nexception
from neutron.extensions import l3


RATE_LIMIT = 'rate_limit'

# maybe this configuration is not necessary
fip_ratelimits_cds_opts = [
    cfg.IntOpt('maximum_ratelimit', default=0,
               help=_("The fip's maximum ratelimit which user can specify, " +
                      "Zero or negative means no maximum restrict. " +
                      "The unit is Mbps")),
]

cfg.CONF.register_opts(fip_ratelimits_cds_opts, 'cds_conf')


class InvalidRatelimit(nexception.InvalidInput):
    message = _("Floating IP's rate limit should be a positve integer and "
                "divisible by 1024")


class OverMaximum(nexception.InvalidInput):
    message = _("Input ratelimit is %(input)s which allowed "
                "%(maximum)s at max")


def _validate_rate_limit(rate_limit, valid_values=None):
    if (attr.validators["type:non_negative"](rate_limit) or
            rate_limit == 0 or rate_limit % 1024 != 0):
        raise InvalidRatelimit()

    maximum = cfg.CONF.cds_conf.maximum_ratelimit * 1024
    if maximum > 0 and rate_limit > maximum:
        raise OverMaximum(maximum=maximum, input=rate_limit)

attr.validators['type:fip_rate_limit'] = _validate_rate_limit

EXTENDED_ATTRIBUTES_2_0 = {
    l3.FLOATINGIPS: {
        # NOTE(gongysh) since we have no update floatingip API,
        # the allow_put is given as False, but we use a special API
        # to change the ratelimit
        RATE_LIMIT: {'allow_post': True, 'allow_put': False,
                     'convert_to': attr.convert_to_int,
                     'validate': {'type:fip_rate_limit': None},
                     'is_visible': True, 'default': 1024},
    }
}


class Floatingip_ratelimits(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "FloatingIP RateLimit Extension"

    @classmethod
    def get_alias(cls):
        return "floatingip_ratelimits"

    @classmethod
    def get_description(cls):
        return ("Apply Traffic Rate Limitation on Floating IPs")

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/ext/neutron/"
                "floatingip-ratelimit/api/v1.0")

    @classmethod
    def get_updated(cls):
        return "2014-01-06T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
