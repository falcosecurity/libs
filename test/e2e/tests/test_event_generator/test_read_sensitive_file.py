import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events, SinspField


def create_containers(sinsp_filter, syscall):
    return {
        'sinsp': sinsp.container_spec(args=sinsp_filter),
        'generator': event_generator.container_spec('syscall.ReadSensitiveFileUntrusted')
    }


sinsp_filters = ["-f", "evt.type in (open,openat,openat2) and evt.is_open_read=true and fd.typechar='f' and fd.num>=0"]
containers = [
    create_containers(sinsp_filters, 'syscall.ReadSensitiveFileUntrusted'),
    create_containers(sinsp_filters, 'syscall.ReadSensitiveFileTrustedAfterStartup'),
]


@pytest.mark.parametrize("run_containers", containers, indirect=True)
def test_read_sensitive_file(run_containers):
    sinsp_container = run_containers['sinsp']

    generator_container = run_containers['generator']
    generator_container.wait()

    expected_events = [
        {
            "evt.args": SinspField.regex_field(r'fd=3\(<f>/etc/shadow\) dirfd=-100\(AT_FDCWD\) name=/etc/shadow flags=4097\(O_RDONLY|O_CLOEXEC\) mode=0 dev=\W+ ino=\d+ '),
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": "<",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "openat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        }
    ]

    assert_events(expected_events, sinsp_container)
