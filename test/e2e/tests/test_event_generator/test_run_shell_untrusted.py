import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events, SinspField
from sinspqa.docker import get_container_id


containers = [{
    'generator': event_generator.container_spec('syscall.RunShellUntrusted')
}]

sinsp_filters = ["-f", "evt.type in (execve, execveat) and evt.dir=<"]
sinsp_examples = [
    sinsp_example for sinsp_example in sinsp.generate_specs(args=sinsp_filters)
]
ids = [
    sinsp.generate_id(sinsp_example) for sinsp_example in sinsp_examples
]

@pytest.mark.parametrize('sinsp', sinsp_examples, indirect=True, ids=ids)
@pytest.mark.parametrize("run_containers", containers, indirect=True)
def test_run_shell_untrusted(sinsp, run_containers: dict):
    generator_container = run_containers['generator']
    generator_id = get_container_id(generator_container)
    generator_container.wait()

    expected_events = [
        {
            "container.id": generator_id,
            "evt.args": SinspField.regex_field(r'^res=0 exe=\/tmp\/falco-event-generator\d+\/httpd args=--loglevel.info.run.\^helper.RunShell\$. tid=\d+\(httpd\) pid=\d+\(httpd\) ptid=\d+\(event-generator\) .* tty=0 pgid=\d+\(systemd\) loginuid=-1\(\<NONE\>\) flags=1\(EXE_WRITABLE\) cap_inheritable=0'),
            "evt.category": "process",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "execve",
            "proc.cmdline": "httpd --loglevel info run ^helper.RunShell$",
            "proc.exe": SinspField.regex_field(r'^\/tmp\/falco-event-generator\d+\/httpd$'),
            "proc.pid": SinspField.numeric_field(),
            "proc.ppid": SinspField.numeric_field()
        },
        {
            "container.id": generator_id,
            "evt.args": SinspField.regex_field(r'^res=0 exe=bash args=-c.ls > \/dev\/null. tid=\d+\(bash\) pid=\d+\(bash\) ptid=\d+\(httpd\) .* tty=0 pgid=\d+\(systemd\) loginuid=-1\(\<NONE\>\) flags=1\(EXE_WRITABLE\) cap_inheritable=0'),
            "evt.category": "process",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "execve",
            "proc.cmdline": "bash -c ls > /dev/null",
            "proc.exe": "bash",
            "proc.pid": SinspField.numeric_field(),
            "proc.ppid": SinspField.numeric_field()
        },
    ]

    assert_events(expected_events, sinsp)
