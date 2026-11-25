from types import SimpleNamespace

from lib.compiler import Compiler


def test_msvc_failure_does_not_accept_stale_executable(monkeypatch, tmp_path):
    compiler = Compiler({"type": "msvc", "language": "c", "output_dir": str(tmp_path)})
    monkeypatch.setattr(compiler, "_find_vcvars", lambda: "vcvars64.bat")
    monkeypatch.setattr(
        "lib.compiler.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="compiler error",
            stderr="",
        ),
    )

    stale = tmp_path / "loader.exe"
    stale.write_bytes(b"old executable")

    result = compiler.compile("int main(void) { return 0; }", "loader", output_dir=str(tmp_path))

    assert result.success is False
    assert result.output_path is None
    assert "exit code 1" in result.error
    assert not stale.exists()


def test_msvc_success_requires_executable_from_current_compile(monkeypatch, tmp_path):
    compiler = Compiler({"type": "msvc", "language": "c", "output_dir": str(tmp_path)})
    monkeypatch.setattr(compiler, "_find_vcvars", lambda: "vcvars64.bat")

    output = tmp_path / "loader.exe"

    def successful_compile(*args, **kwargs):
        output.write_bytes(b"new executable")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("lib.compiler.subprocess.run", successful_compile)

    result = compiler.compile("int main(void) { return 0; }", "loader", output_dir=str(tmp_path))

    assert result.success is True
    assert result.output_path == str(output.absolute())
    assert output.read_bytes() == b"new executable"


def test_mingw_failure_does_not_accept_stale_executable(monkeypatch, tmp_path):
    compiler = Compiler({"type": "mingw", "language": "c", "output_dir": str(tmp_path)})
    monkeypatch.setattr(
        "lib.compiler.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="compiler error",
        ),
    )

    stale = tmp_path / "loader.exe"
    stale.write_bytes(b"old executable")

    result = compiler.compile("int main(void) { return 0; }", "loader", output_dir=str(tmp_path))

    assert result.success is False
    assert "exit code 1" in result.error
    assert not stale.exists()
