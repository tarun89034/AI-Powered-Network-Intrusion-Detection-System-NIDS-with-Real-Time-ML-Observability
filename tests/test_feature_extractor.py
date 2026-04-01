from nids_engine.features.feature_extractor import FeatureExtractor


def test_flow_accumulation_no_premature_emit():
    """Packets should accumulate into a flow without premature emission on FIN/RST."""
    emitted = []
    extractor = FeatureExtractor(flow_timeout=60, callback=emitted.append)

    pkt1 = {
        "timestamp": 1.0,
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "ip_len": 100,
        "protocol": "TCP",
        "src_port": 1111,
        "dst_port": 80,
        "flags": "PA",
    }
    pkt2 = {
        "timestamp": 2.0,
        "src_ip": "192.168.1.20",
        "dst_ip": "192.168.1.10",
        "ip_len": 120,
        "protocol": "TCP",
        "src_port": 80,
        "dst_port": 1111,
        "flags": "FA",
    }

    extractor.process_packet(pkt1)
    extractor.process_packet(pkt2)

    # Flow should NOT be emitted yet — true flow-based detection waits for timeout
    assert len(emitted) == 0
    assert len(extractor.flows) == 1


def test_flow_emits_on_timeout():
    """Flows should only be emitted after the inactivity timeout expires."""
    emitted = []
    extractor = FeatureExtractor(flow_timeout=5, callback=emitted.append)

    pkt1 = {
        "timestamp": 100.0,
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "ip_len": 100,
        "protocol": "TCP",
        "src_port": 1111,
        "dst_port": 80,
        "flags": "PA",
    }
    pkt2 = {
        "timestamp": 101.0,
        "src_ip": "192.168.1.20",
        "dst_ip": "192.168.1.10",
        "ip_len": 120,
        "protocol": "TCP",
        "src_port": 80,
        "dst_port": 1111,
        "flags": "FA",
    }

    extractor.process_packet(pkt1)
    extractor.process_packet(pkt2)

    # Not expired yet
    extractor.cleanup_expired_flows(103.0)
    assert len(emitted) == 0

    # Now past timeout (101.0 + 5 = 106.0)
    extractor.cleanup_expired_flows(107.0)
    assert len(emitted) == 1

    flow = emitted[0]
    feats = flow["features"]

    assert flow["protocol"] == "TCP"
    assert feats["Total Fwd Packets"] == 1
    assert feats["Total Backward Packets"] == 1
    assert feats["Total Length of Fwd Packets"] == 100
    assert feats["Total Length of Bwd Packets"] == 120
    assert feats["ACK Flag Count"] == 1
    assert feats["FIN Flag Count"] == 1
