from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP

from nids_engine.parser.packet_parser import PacketParser


def test_parse_http_packet():
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="PA")
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )

    parsed = PacketParser.parse_packet(packet)

    assert parsed is not None
    assert parsed["protocol"] == "TCP"
    assert parsed["src_port"] == 12345
    assert parsed["dst_port"] == 80
    assert parsed["dpi_protocol"] == "HTTP"
    assert parsed["http_method"] == "GET"


def test_parse_dns_packet():
    packet = (
        IP(src="10.0.0.3", dst="8.8.8.8")
        / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.org"))
    )

    parsed = PacketParser.parse_packet(packet)

    assert parsed is not None
    assert parsed["protocol"] == "UDP"
    assert parsed["dpi_protocol"] == "DNS"
    assert "example.org" in (parsed["dns_query"] or "")
