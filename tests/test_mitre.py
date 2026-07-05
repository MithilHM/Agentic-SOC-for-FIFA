"""MITRE ATT&CK catalogue loader + mapping tests."""
import pytest

from intel import mitre


@pytest.fixture(autouse=True)
def _reset_catalogue_cache():
    mitre._catalogue = None
    yield
    mitre._catalogue = None


def test_catalogue_loads_full_enterprise_set():
    cat = mitre.load_catalogue()
    # The catalogue was pre-extracted from the full ATT&CK Enterprise bundle.
    assert len(cat) > 600
    # Known technique from the bundle.
    assert "T1055.011" in cat
    assert cat["T1055.011"]["name"] == "Extra Window Memory Injection"


def test_catalogue_is_cached_across_calls():
    first = mitre.load_catalogue()
    second = mitre.load_catalogue()
    assert first is second   # same object, not re-read from disk


def test_lookup_known_technique():
    info = mitre.lookup_technique("T1055.011")
    assert info["name"] == "Extra Window Memory Injection"
    assert info["source"] == "mitre-attack-catalogue"
    assert isinstance(info["tactics"], list)


def test_lookup_unknown_technique_falls_back():
    info = mitre.lookup_technique("T9999.999")
    assert info["source"] == "unknown"
    assert info["name"] is None
    assert "No description" in info["description"]


def test_missing_catalogue_file_degrades_gracefully(tmp_path):
    missing = str(tmp_path / "does_not_exist.json")
    cat = mitre.load_catalogue(missing)
    assert cat == {}


def test_map_to_attack_static_pairs():
    assert mitre.map_to_attack("Phishing") == ("Initial Access", "T1566")
    assert mitre.map_to_attack("BruteForce") == ("Credential Access", "T1110")
    # Unknown event type -> no mapping.
    assert mitre.map_to_attack("SomethingElse") == (None, None)
