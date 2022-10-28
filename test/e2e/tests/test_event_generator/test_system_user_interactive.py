import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events, SinspField
from sinspqa.docker import get_container_id

sinsp_filters = ["-f", "evt.type in (execve, execveat) and evt.dir=<"]

containers = [{
    'sinsp': sinsp_container,
    'generator': event_generator.container_spec('syscall.SystemUserInteractive')
} for sinsp_container in sinsp.generate_specs(args=sinsp_filters)]

ids = [
    f'{sinsp.generate_id(c["sinsp"])}-{event_generator.generate_id(c["generator"])}'
    for c in containers
]


@pytest.mark.parametrize("run_containers", containers, indirect=True, ids=ids)
def test_system_user_interactive(run_containers: dict):
    sinsp_container = run_containers['sinsp']

    generator_container = run_containers['generator']
    generator_id = get_container_id(generator_container)
    generator_container.wait()

    expected_events = [
        {
            "container.id": generator_id,
            "evt.args": SinspField.regex_field(r'^res=0 exe=\/bin\/login args=NULL tid=\d+\(login\) pid=\d+\(login\) ptid=\d+\(event-generator\) .* pgid=\d+\(systemd\) loginuid=-1 flags=0 cap_inheritable=0 cap_permitted=0 cap_effective=0 $'),
            "evt.category": "process",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "execve",
            "proc.cmdline": "login",
            "proc.exe": "/bin/login",
            "proc.pid": SinspField.numeric_field(),
            "proc.ppid": SinspField.numeric_field()
        }
    ]

    assert_events(expected_events, sinsp_container)
