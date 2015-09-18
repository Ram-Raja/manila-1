
CephFS Native driver
====================

The CephFS Native driver enables Manila to export shared filesystems to guests
using the Ceph network protocol.  Guests require a Ceph client in order to
mount the filesystem.

Access is controlled via Ceph's cephx authentication system.  Each share has
a distinct authentication key that must be passed to clients for them to use it.

Prerequisities
==============

- A Ceph cluster with a filesystem configured (http://docs.ceph.com/docs/master/cephfs/createfs/)
- Network connectivity between your Ceph cluster's public network and your manila server
- Network connectivity between your Ceph cluster's public network and guests

.. important:: A Manila share backed onto CephFS is only as good as the underlying filesystem.  Take
               care when configuring your Ceph cluster, and consult the latest guidance on the use of
               CephFS in the Ceph documentation (http://docs.ceph.com/docs/master/cephfs/)

Authorize the driver to communicate with Ceph
=============================================

::

    ceph auth get-or-create client.manila mon 'allow r; allow command "auth del" with entity prefix client.manila.; allow command "auth caps" with entity prefix client.manila.; allow command "auth get" with entity prefix client.manila., allow command "auth get-or-create" with entity prefix client.manila.' mds 'allow *' osd 'allow rw' > keyring.manila

keyring.manila, along with your ceph.conf file, will then need to be placed
on your manila server, and the paths to these configured in your manila.conf.


Enable snapshots in Ceph, if you want to use them in Manila:

::

    ceph mds set allow_new_snaps true --yes-i-really-mean-it

Configure CephFS Backend in manila.conf
=======================================

 * Add CephFS to ``enabled_share_protocols`` (enforced at manila api layer)

Create a section like this (defines a backend):
::

    [cephfs1]
    driver_handles_share_servers = False
    share_backend_name = CEPHFS1
    share_driver = manila.share.drivers.cephfs.CephFSNativeDriver
    cephfs_conf_path = /etc/ceph/ceph.conf
    cephfs_auth_id = manila

Then edit ``enabled_share_backends`` to point to it

Creating shares
===============

The default share type may have driver_handles_share_servers set to true.  Configure
a share type suitable for cephfs:

::

     manila type-create cephfstype false

Then create yourself a share:

::

    manila create --share-type cephfstype --name cephshare1 cephfs 1


Mounting a client with FUSE
===========================

Using the key from your export location, and the share ID, create a keyring file like

::

    [client.share-4c55ad20-9c55-4a5e-9233-8ac64566b98c]
            key = AQA8+ANW/4ZWNRAAOtWJMFPEihBA1unFImJczA==

Using the mon IP addresses from your export location, create a ceph.conf file like:

::

    [client]
            client quota = true

    [mon.a]
            mon addr = 192.168.1.7:6789

    [mon.b]
            mon addr = 192.168.1.8:6789

    [mon.c]
            mon addr = 192.168.1.9:6789

Finally, mount the filesystem, substituting the filenames of the keyring and
configuration files you just created:

::

    ceph-fuse --id=share-4c55ad20-9c55-4a5e-9233-8ac64566b98c -c ./client.conf --keyring=./client.keyring --client-mountpoint=/volumes/share-4c55ad20-9c55-4a5e-9233-8ac64566b98c ~/mnt
