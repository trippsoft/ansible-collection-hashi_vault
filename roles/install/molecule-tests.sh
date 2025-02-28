#! /bin/bash

set -e

MOLECULE_BOX="rocky9_cis" molecule test -s raft_standalone
MOLECULE_BOX="rocky9_cis" molecule test -s raft_cluster

MOLECULE_BOX="debian12_base" molecule test -s raft_standalone
MOLECULE_BOX="debian12_base" molecule test -s raft_cluster

MOLECULE_BOX="fedora41_base" molecule test -s raft_standalone
MOLECULE_BOX="fedora41_base" molecule test -s raft_cluster

MOLECULE_BOX="ubuntu2404_base" molecule test -s raft_standalone
MOLECULE_BOX="ubuntu2404_base" molecule test -s raft_cluster

MOLECULE_BOX="rocky8_cis" molecule test -s raft_standalone
MOLECULE_BOX="rocky8_cis" molecule test -s raft_cluster

MOLECULE_BOX="debian11_base" molecule test -s raft_standalone
MOLECULE_BOX="debian11_base" molecule test -s raft_cluster

MOLECULE_BOX="ubuntu2204_base" molecule test -s raft_standalone
MOLECULE_BOX="ubuntu2204_base" molecule test -s raft_cluster

MOLECULE_BOX="ubuntu2004_base" molecule test -s raft_standalone
MOLECULE_BOX="ubuntu2004_base" molecule test -s raft_cluster
