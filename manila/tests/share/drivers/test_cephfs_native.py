
import sys

from oslo_config import cfg
from manila import test
from manila import context

from manila.share import configuration
from manila.share.drivers import cephfs
from manila.db.sqlalchemy.models import ShareInstance

import mock
from manila.tests import fake_share
from manila.tests.db import fakes as db_fakes
from manila.share import share_types

CONF = cfg.CONF


def fake_share_instance(base_share=None, **kwargs):
    if base_share is None:
        share = fake_share.fake_share()
    else:
        share = base_share

    share_instance = {
        'share_id': share['id'],
        'id': "fakeinstanceid",
        'status': "active",
    }

    for attr in ShareInstance._proxified_properties:
        share_instance[attr] = getattr(share, attr, None)

    return db_fakes.FakeModel(share_instance)


class VolumePath(object):
    """
    Copy of VolumePath from VolumeClient (it's so simple that I can live with the copy-paste)
    """
    def __init__(self, group_id, volume_id):
        self.group_id = group_id
        self.volume_id = volume_id

    def __eq__(self, other):
        return self.group_id == other.group_id and self.volume_id == other.volume_id

    def __str__(self):
        return "{0}/{1}".format(self.group_id, self.volume_id)


class MockVolumeClientModule(object):
    """
    Mocked up version of ceph's VolumeClient interface
    """
    VolumePath = VolumePath

    class CephFSVolumeClient(mock.Mock):
        def __init__(self, *args, **kwargs):
            mock.Mock.__init__(self, spec=["connect", "disconnect"])
            self.create_volume = mock.Mock(return_value={
                "mount_path": "/foo/bar"
            })
            self.get_mon_addrs = mock.Mock(return_value=
                                           ["1.2.3.4", "5.6.7.8"]
                                           )
            self.authorize = mock.Mock(return_value=
                                       "abc123"
                                       )


class CephFSNativeDriverTestCase(test.TestCase):
    """
    Test the CephFS native driver.  This is a very simple driver that mainly
    calls through to 
    """
    def setUp(self):
        super(CephFSNativeDriverTestCase, self).setUp()
        self.fake_conf = configuration.Configuration(None)
        self._context = context.get_admin_context()
        self._share_instance = fake_share_instance(fake_share.fake_share(share_proto='CEPHFS'))

        # As soon as the driver tries to initialize volume_client, it'll
        # see our fake instead
        sys.modules["ceph_volume_client"] = MockVolumeClientModule

        self._driver = cephfs.CephFSNativeDriver(configuration=self.fake_conf)

        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value={}))

    def test_create_share(self):
        export_location = self._driver.create_share(self._context, self._share_instance)
        self.assertEqual(export_location, "1.2.3.4,5.6.7.8:/foo/bar:abc123")

    def test_data_isolated(self):
        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value={"data_isolated": True}))
        self._driver.create_share(self._context, self._share_instance)
        self._driver._volume_client.create_volume.assert_called_once_with(
            self._driver._share_path(self._share_instance),
            size=self._share_instance['size'] * 1024 * 1024 * 1024,
            data_isolated=True)
