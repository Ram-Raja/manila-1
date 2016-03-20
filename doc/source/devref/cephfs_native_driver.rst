
CephFS Native driver
====================

The CephFS Native driver enables manila to export shared filesystems to guests
using the Ceph network protocol.  Guests require a Ceph client in order to
mount the filesystem.

Access is controlled via Ceph's cephx authentication system.  So when a user
requests access to a share for an ID, Ceph creates a corresponding Ceph auth ID
and a secret key, if they does not already exist, and authorizes the ID to
access the share.  The client can then mount the share using the secret key.

To learn more about configuring Ceph clients to access the shares created
using this driver, please see the Ceph documentation(
http://docs.ceph.com/docs/master/cephfs/).  If you choose to use the kernel
client rather than the FUSE client, the share size limits set in Manila
may not be obeyed.

Supported Operations
--------------------

The following operations are supported with CephFS backend:

- Create/delete CephFS share
- Allow/deny CephFS share access

  * ``cephx`` access type is supported for CephFS protocol.
  * Read/write is supported.

- Extend/shrink share
- Create/delete snapshot
- Create/delete consistency group (CG)
- Create/delete CG snapshot

Prerequisities
--------------

- A Ceph cluster with a filesystem configured (
  http://docs.ceph.com/docs/master/cephfs/createfs/)
- Network connectivity between your Ceph cluster's public network and the
  servers running the :term:`manila-share` service.  ``ceph-common`` package
  needs to be installed in the :term: `manila-share` servers.
- Network connectivity between your Ceph cluster's public network and guests.
- Jewel or later version of Ceph packages.

.. important:: A manila share backed onto CephFS is only as good as the
               underlying filesystem.  Take care when configuring your Ceph
               cluster, and consult the latest guidance on the use of
               CephFS in the Ceph documentation (
               http://docs.ceph.com/docs/master/cephfs/)

Authorize the driver to communicate with Ceph
---------------------------------------------

Run the following command to create a Ceph identity for manila to use:

.. code-block:: console

    ceph auth get-or-create client.manila mon 'allow r; allow command "auth del" with entity prefix client.manila.; allow command "auth caps" with entity prefix client.manila.; allow command "auth get" with entity prefix client.manila., allow command "auth get-or-create" with entity prefix client.manila.' mds 'allow *' osd 'allow rw' > keyring.manila

keyring.manila, along with your ceph.conf file, will then need to be placed
on the server where the :term:`manila-share` service runs, and the paths to
these configured in your manila.conf.


Enable snapshots in Ceph if you want to use them in manila:

.. code-block:: console

    ceph mds set allow_new_snaps true --yes-i-really-mean-it

Configure CephFS backend in manila.conf
---------------------------------------

Add CephFS to ``enabled_share_protocols`` (enforced at manila api layer).  In
this example we leave NFS and CIFS enabled, although you can remove these
if you will only use CephFS:

.. code-block:: ini

    enabled_share_protocols = NFS,CIFS,CEPHFS

Create a section like this to define a CephFS backend:

.. code-block:: ini

    [cephfs1]
    driver_handles_share_servers = False
    share_backend_name = CEPHFS1
    share_driver = manila.share.drivers.cephfs.cephfs_native.CephFSNativeDriver
    cephfs_conf_path = /etc/ceph/ceph.conf
    cephfs_auth_id = manila
    cephfs_cluster_name = ceph
    cephfs_enable_snapshots = True

Set ``cephfs_enable_snapshots`` to True in the section to let the driver
perform snapshot related operations.

Then edit ``enabled_share_backends`` to point to the driver's backend section
using the section name.  In this example we are also including another backend
("generic1"), you would include whatever other backends you have configured.


.. code-block:: ini

    enabled_share_backends = generic1, cephfs1


Creating shares
---------------

The default share type may have ``driver_handles_share_servers`` set to True.
Configure a share type suitable for cephfs:

.. code-block:: console

     manila type-create cephfstype false

Then create yourself a share:

.. code-block:: console

    manila create --share-type cephfstype --name cephshare1 cephfs 1

Note the export location of the share:

.. code-block:: console

    manila share-export-location-list cephshare1

The export location of the share contains the Ceph monitor (mon) addresses and
ports, and the path to be mounted.  It is of the form,
``{mon ip addr:port}[,{mon ip addr:port}]:{path to be mounted}``


Allowing access to shares
--------------------------

Allow user ID ``alice`` access to the share using ``cephx`` access type.

.. code-block:: console

    manila access-allow cephshare1 cephx alice


Mounting shares using FUSE client
---------------------------------

Using the secret key of the authorized ID ``alice`` that is passed to you by
the Ceph admin, create a keyring file, ``alice.keyring`` like:

.. code-block:: ini

    [client.alice]
            key = AQA8+ANW/4ZWNRAAOtWJMFPEihBA1unFImJczA==

Using the mon IP addresses from the share's export location, create a
configuration file, ``ceph.conf`` like:

.. code-block:: ini

    [client]
            client quota = true
            mon host = 192.168.1.7:6789, 192.168.1.8:6789, 192.168.1.9:6789

Finally, mount the filesystem, substituting the filenames of the keyring and
configuration files you just created, and substituting the path to be mounted
from the share's export location:

.. code-block:: console

    sudo ceph-fuse --id=alice --conf=./ceph.conf --keyring=./alice.keyring --client-mountpoint=/volumes/_nogroup/4c55ad20-9c55-4a5e-9233-8ac64566b98c ~/mnt


Known restrictions
------------------

Mitaka release

 Consider the driver as a building block for supporting multi-tenant
 workloads in the future.  It can be used in private cloud deployments.

- The secret-key required to mount a share is not exposed by manila APIs.  It
  needs to be shared with the guest by the Ceph admin out of band of manila.

- Snapshots are read-only and can be read from
  ``.snap/share-snapshot-{manila-snapshot-id}`` folder within the mounted
  share.  Shares cannot be created from snapshots.
