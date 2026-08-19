from netsleuth.cli import parse_target

def test_parse_target_asn_with_prefix():
    assert parse_target("AS12345") == ("asn", "AS12345")
    assert parse_target("as12345") == ("asn", "AS12345")
    assert parse_target("aS12345") == ("asn", "AS12345")

def test_parse_target_asn_digits_only():
    assert parse_target("12345") == ("asn", "AS12345")

def test_parse_target_ipv4():
    assert parse_target("192.168.1.1") == ("ip", "192.168.1.1")
    assert parse_target("8.8.8.8") == ("ip", "8.8.8.8")

def test_parse_target_ipv6():
    assert parse_target("2001:4860:4860::8888") == ("ip", "2001:4860:4860::8888")
    assert parse_target("::1") == ("ip", "::1")

def test_parse_target_domain():
    assert parse_target("example.com") == ("domain", "example.com")
    assert parse_target("localhost") == ("domain", "localhost")
    assert parse_target("AS123X") == ("domain", "AS123X")
    assert parse_target("192.168.1") == ("domain", "192.168.1")

def test_parse_target_whitespace_stripping():
    assert parse_target("  AS12345  ") == ("asn", "AS12345")
    assert parse_target("\n8.8.8.8\t") == ("ip", "8.8.8.8")
    assert parse_target(" example.com ") == ("domain", "example.com")
