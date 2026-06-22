#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_bfd_opt_auth_topo1.py: BFD RFC 9985 optimized authentication interop.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bfdd]


def setup_module(mod):
    topodef = {"s1": ("rt1:eth-rt2", "rt2:eth-rt1")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _opt_auth_enabled():
    tgen = get_topogen()
    out = tgen.gears["rt1"].vtysh_cmd("show version", isjson=False)
    return "bfd-opt-auth" in out or "BFD_OPT_AUTH" in out


def _configure_opt_auth(rname, peer_ip, ifname):
    tgen = get_topogen()
    router = tgen.gears[rname]
    router.vtysh_cmd(
        "\n".join(
            [
                "configure terminal",
                "key chain OPTKC",
                " key 1",
                "  cryptographic-algorithm optimized-sha1-meticulous-keyed-isaac",
                "  key-string OPTAUTHKEY",
                " exit",
                "exit",
                "bfd",
                " peer {} interface {}".format(peer_ip, ifname),
                "  authentication key-chain OPTKC",
                "  authentication optimized",
                "  authentication reauth-interval 60",
                " exit",
                "exit",
            ]
        ),
        isjson=False,
    )


def test_bfd_opt_auth_session_up():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if not _opt_auth_enabled():
        pytest.skip("FRR not built with --enable-bfd-opt-auth")

    _configure_opt_auth("rt1", "10.0.1.2", "eth-rt2")
    _configure_opt_auth("rt2", "10.0.1.1", "eth-rt1")

    def _check(_):
        output = tgen.gears["rt1"].vtysh_cmd("show bfd peers json", isjson=True)
        peer = output.get("peer")
        assert peer is not None
        for peers in peer.values():
            for entry in peers:
                if entry.get("status") == "up":
                    auth = entry.get("authentication", {})
                    if auth.get("enabled"):
                        return None
        return "waiting for optimized-auth BFD session up"

    _, diff = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert diff is None, "BFD optimized auth session failed to reach Up"
