import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events, SinspField

generator_containers = [
    event_generator.container_spec(syscall)
    for syscall in [
            'syscall.ReadSensitiveFileUntrusted',
            'syscall.ReadSensitiveFileTrustedAfterStartup'
        ]
]
expected_processes = [
    'event-generator',
    'httpd'
]
generator_tuples = zip(generator_containers, expected_processes)

sinsp_filters = [
    "-f", "evt.type in (open,openat,openat2) and evt.is_open_read=true and fd.typechar='f' and fd.num>=0"]
parameters = [
    (
        {
            'sinsp': sinsp_container,
            'generator': generator_container,
        },
        expected_process
    )
    for (generator_container, expected_process) in generator_tuples
    for sinsp_container in sinsp.generate_specs(args=sinsp_filters)
]


def generate_ids(parameters: list) -> list:
    ret = []

    for parameter in parameters:
        containers = parameter[0]
        sinsp_id = sinsp.generate_id(containers['sinsp'])
        generator_id = event_generator.generate_id(containers['generator'])

        ret.append(f'{sinsp_id}-{generator_id}')

    return ret


@pytest.mark.parametrize("run_containers,expected_process", parameters, indirect=['run_containers'], ids=generate_ids(parameters))
def test_read_sensitive_file(run_containers: dict, expected_process: str):
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
            "proc.name": expected_process,
            "thread.tid": SinspField.numeric_field()
        }
    ]

    assert_events(expected_events, sinsp_container)
