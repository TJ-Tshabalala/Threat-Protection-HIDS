from agent.agent import collect_basic_info


def test_collect_basic_info_has_keys():
    info = collect_basic_info()
    assert "hostname" in info
    assert "os" in info
    assert isinstance(info.get("processes", []), list)
