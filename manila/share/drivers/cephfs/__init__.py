# Copyright (c) 2015 Red Hat, Inc.
# All Rights Reserved.
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


from oslo_log import log
from oslo_config import cfg

from manila.i18n import _
import manila.exception as exception
from manila.share import driver
from manila.share import share_types


CEPHX_ACCESS_TYPE = "cephx"

# The default Ceph administrative identity
CEPH_DEFAULT_AUTH_ID = "admin"


log = log.getLogger(__name__)


cephfs_native_opts = [
    cfg.StrOpt('cephfs_conf_path',
               default="",
               help=""),
    cfg.StrOpt('cephfs_cluster_name',
               default=None,
               help="The name of the cluster in use, if it is not the default ('ceph')"
               ),
    cfg.StrOpt('cephfs_auth_id',
               default="manila",
               help="The name of the ceph auth identity to use.  Default 'manila'."
               ),
]


CONF = cfg.CONF
CONF.register_opts(cephfs_native_opts)


class CephFSNativeDriver(driver.ShareDriver,):
    """
    This driver is 'native' in the sense that it exposes a CephFS filesystem
    for use directly by guests, with no intermediate layer.
    """

    supported_protocols = ('CEPHFS',)
    driver_handles_share_servers = False

    # We support snapshots, but not creating shares from them (yet)
    _snapshots_are_supported = True

    def get_share_stats(self, refresh=False):
        data = super(CephFSNativeDriver, self).get_share_stats(refresh)
        data['consistency_group_support'] = 'pool'
        data['vendor_name'] = 'Red Hat'
        data['driver_version'] = '1.0'
        return data

    def _to_bytes(self, gigs):
        """
        Convert a Manila size into bytes.  Manila uses gigs everywhere.  If the input
        is None, return None.

        :param gigs: integer number of gigabytes
        :return: integer number of bytes
        """
        if gigs is not None:
            return gigs * 1024 * 1024 * 1024
        else:
            return None

    @property
    def volume_client(self):
        if self._volume_client:
            return self._volume_client

        try:
            from ceph_volume_client import CephFSVolumeClient
        except ImportError as e:
            raise exception.ManilaException(
                "Ceph client libraries not found: {0}".format(
                    e
                )
            )
        else:
            conf_path = self.configuration.safe_get('cephfs_conf_path')
            cluster_name = self.configuration.safe_get('cephfs_cluster_name')
            auth_id = self.configuration.safe_get('cephfs_auth_id')
            self._volume_client = CephFSVolumeClient(auth_id, conf_path, cluster_name)
            log.info("Ceph client found, connecting...")
            if auth_id != CEPH_DEFAULT_AUTH_ID:
                # Evict any other manila sessions.  Only do this if we're using a client ID
                # that isn't the default admin ID, to avoid rudely disrupting anyone else.
                premount_evict = auth_id
            else:
                premount_evict = None
            try:
                self._volume_client.connect(premount_evict=premount_evict)
            except Exception:
                self._volume_client = None
                raise
            else:
                log.info("Ceph client connection complete")

            return self._volume_client

    def __init__(self, *args, **kwargs):
        super(CephFSNativeDriver, self).__init__(
            False, *args, **kwargs)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'CephFS-Native'

        self._volume_client = None

        self.configuration.append_config_values(cephfs_native_opts)

    def _share_path(self, share):
        """
        Get VolumePath from ShareInstance
        """
        from ceph_volume_client import VolumePath
        return VolumePath(share['consistency_group_id'], share['share_id'])

    def create_share(self, context, share, share_server=None):
        """

        :param context: A RequestContext
        :param share: A ShareInstance
        :param share_server: Always None for CephFS native
        :return:
        """

        assert share_server is None

        # `share` is a ShareInstance
        log.info("create_share name={0} size={1} cg_id={2}".format(
            share['share_id'], share['size'], share['consistency_group_id']))

        extra_specs = share_types.get_extra_specs_from_share(share)
        data_isolated = extra_specs.get("data_isolated", False)

        size = self._to_bytes(share['size'])

        # Create the CephFS volume
        volume = self.volume_client.create_volume(
            self._share_path(share), size=size, data_isolated=data_isolated)

        # To mount this you need to know the mon IPs, the volume name, and they key
        mon_addrs = self.volume_client.get_mon_addrs()

        export_location = "{0}:{1}".format(
            ",".join(mon_addrs),
            volume['mount_path'])

        log.info("Calculated export location: {0}".format(export_location))

        return export_location

    def allow_access(self, context, share, access, share_server=None):
        if access['access_type'] != CEPHX_ACCESS_TYPE:
            raise exception.InvalidShareAccess(_("Only 'cephx' access type allowed"))

        ceph_auth_id = access['access_to']

        auth_result = self.volume_client.authorize(self._share_path(share), ceph_auth_id)

        return auth_result['auth_key']

    def deny_access(self, context, share, access, share_server=None):
        self.volume_client.deauthorize(self._share_path(share), access['access_to'])

    def delete_share(self, context, share, share_server=None):
        extra_specs = share_types.get_extra_specs_from_share(share)
        data_isolated = extra_specs.get("data_isolated", False)

        auth_name = share['share_id']
        self.volume_client.deauthorize(self._share_path(share), auth_name)
        self.volume_client.evict(auth_name)
        self.volume_client.delete_volume(self._share_path(share), data_isolated=data_isolated)
        self.volume_client.purge_volume(self._share_path(share), data_isolated=data_isolated)

    def ensure_share(self, context, share, share_server=None):
        # Creation is idempotent
        return self.create_share(context, share, share_server)

    def extend_share(self, share, new_size, share_server=None):
        log.info("extend_share {0} {1}".format(share['share_id'], new_size))
        self.volume_client.set_max_bytes(self._share_path(share), self._to_bytes(new_size))

    def shrink_share(self, share, new_size, share_server=None):
        log.info("shrink_share {0} {1}".format(share['share_id'], new_size))
        new_bytes = self._to_bytes(new_size)
        used = self.volume_client.get_used_bytes(self._share_path(share))
        if used > new_bytes:
            # While in fact we can "shrink" our volumes to less than their
            # used bytes (it's just a quota), raise error anyway to avoid
            # confusing API consumers that might depend on typical shrink
            # behaviour.
            raise exception.ShareShrinkingPossibleDataLoss()

        self.volume_client.set_max_bytes(self._share_path(share), new_bytes)

    def create_snapshot(self, context, snapshot, share_server=None):
        self.volume_client.create_snapshot_volume(
            self._share_path(snapshot['share']),
            snapshot['name'])

    def delete_snapshot(self, context, snapshot, share_server=None):
        # We assign names to created snapshots
        assert snapshot['name'] is not None

        self.volume_client.destroy_snapshot_volume(self._share_path(snapshot['share']), snapshot['name'])
        return None

    def create_consistency_group_from_cgsnapshot(self, context, cg_dict, cgsnapshot_dict, share_server=None):
        # TODO
        raise NotImplementedError()

    def create_consistency_group(self, context, cg_dict, share_server=None):
        self.volume_client.create_group(cg_dict['id'])

    def delete_consistency_group(self, context, cg_dict, share_server=None):
        self.volume_client.destroy_group(cg_dict['id'])

    def delete_cgsnapshot(self, context, snap_dict, share_server=None):
        self.volume_client.destroy_snapshot_group(
            snap_dict['consistency_group_id'],
            snap_dict['id']
        )

        return None, []

    def create_cgsnapshot(self, context, snap_dict, share_server=None):
        self.volume_client.create_snapshot_group(
            snap_dict['id'],
            snap_dict['id'])

        return None, []

    def __del__(self):
        if self._volume_client:
            self._volume_client.disconnect()
            self._volume_client = None


    # TODO: create_consistency_group_from_cgsnapshot
    # TODO: create_share_from_snapshot
    # TODO: purge volumes in the background instead of inline in delete_share
    # TODO: populate total_capcity_gb etc capabilities
    # TODO: update openstack-manuals
    # TODO: 90% unit test coverage (1. just set volume_client to a Mock, 2. profit)
