from threat_engine import analyze_device


def test_private_172_network_is_not_penalized_when_expected():
    result = analyze_device(
        {"ip": "172.16.23.10", "mac": "aa:bb:cc:dd:ee:ff"},
        trusted=True,
        expected_network_cidr="172.16.23.0/24",
    )

    assert result["score"] == 0
    assert result["level"] == "LOW"
    assert result["reasons"] == []


def test_untrusted_device_is_explainable():
    result = analyze_device(
        {"ip": "10.0.0.20", "mac": "aa:bb:cc:dd:ee:ff"},
        trusted=False,
        expected_network_cidr="10.0.0.0/24",
    )

    assert result["score"] == 40
    assert result["level"] == "MEDIUM"
    assert any(reason["signal"] == "untrusted_device" for reason in result["reasons"])


def test_outside_expected_network_adds_evidence():
    result = analyze_device(
        {"ip": "10.20.30.40", "mac": "aa:bb:cc:dd:ee:ff"},
        trusted=False,
        expected_network_cidr="192.168.1.0/24",
    )

    assert result["score"] == 65
    assert result["level"] == "HIGH"
    assert any(reason["signal"] == "outside_expected_network" for reason in result["reasons"])
