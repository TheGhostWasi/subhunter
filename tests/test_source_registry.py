import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from subhunter import sources


def test_all_sources_have_required_attributes():
    for module in sources.ALL_SOURCE_MODULES:
        assert hasattr(module, "NAME")
        assert hasattr(module, "REQUIRES_API_KEY")
        assert hasattr(module, "fetch")


def test_key_gated_source_skipped_without_key():
    os.environ.pop("SUBHUNTER_SECURITYTRAILS_API_KEY", None)
    names = sources.available_sources()
    assert "securitytrails" not in names
    assert "crt.sh" in names


def test_key_gated_source_included_with_key():
    os.environ["SUBHUNTER_SECURITYTRAILS_API_KEY"] = "dummy"
    try:
        names = sources.available_sources()
        assert "securitytrails" in names
    finally:
        os.environ.pop("SUBHUNTER_SECURITYTRAILS_API_KEY", None)
