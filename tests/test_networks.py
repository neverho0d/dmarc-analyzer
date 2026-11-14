import ipaddress

import pytest

from dmarc_analyzer import is_ip_in_networks, parse_ip_network, parse_authorized_networks


def test_bare_ipv4_is_slash_32():
    network = parse_ip_network("120.138.21.73")
    assert network == ipaddress.ip_network("120.138.21.73/32")
    assert ipaddress.ip_address("120.138.21.73") in network
    assert ipaddress.ip_address("120.138.21.74") not in network


def test_bare_ipv6_is_slash_128():
    network = parse_ip_network("2403:7000:8000:500::2d")
    assert network == ipaddress.ip_network("2403:7000:8000:500::2d/128")
    assert ipaddress.ip_address("2403:7000:8000:500::2d") in network


def test_cidr_is_kept():
    network = parse_ip_network("120.138.18.240/28")
    assert ipaddress.ip_address("120.138.18.241") in network
    assert ipaddress.ip_address("120.138.18.255") in network
    assert ipaddress.ip_address("120.138.18.239") not in network


def test_authorized_network_list_matches_ipv4_and_ipv6():
    networks = parse_authorized_networks(["120.138.21.73", "2403:7000:8000:500::2d"])
    assert is_ip_in_networks("120.138.21.73", networks)
    assert is_ip_in_networks("2403:7000:8000:500::2d", networks)
    assert not is_ip_in_networks("8.8.8.8", networks)
    assert not is_ip_in_networks("not-an-ip", networks)


def test_invalid_network_raises():
    with pytest.raises(ValueError):
        parse_ip_network("not-an-ip")
