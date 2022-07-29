import pytest
import re
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events, SinspField


def create_expected_arg(directory):
    return fr'^fd=3\(<f>{re.escape(directory)}\/created-by-event-generator\) dirfd=-100\(AT_FDCWD\) name={re.escape(directory)}\/created-by-event-generator flags=4358\(O_TRUNC\|O_CREAT\|O_WRONLY\|O_CLOEXEC\) mode=0755 dev=.* ino=\d+ $'


def generate_ids(parameters: list) -> list:
    ret = []

    for parameter in parameters:
        containers = parameter[0]
        sinsp_id = sinsp.generate_id(containers['sinsp'])
        generator_id = event_generator.generate_id(containers['generator'])

        ret.append(f'{sinsp_id}-{generator_id}')

    return ret


generator_containers = [
    event_generator.container_spec('syscall.WriteBelowEtc'),
    event_generator.container_spec('syscall.WriteBelowBinaryDir'),
    event_generator.container_spec('syscall.CreateFilesBelowDev'),
    event_generator.container_spec('syscall.WriteBelowRpmDatabase')
]
expected_args = [
    create_expected_arg('/etc'),
    create_expected_arg('/bin'),
    create_expected_arg('/dev'),
    create_expected_arg('/var/lib/rpm')
]
generator_tuples = zip(generator_containers, expected_args)

sinsp_filters = [
    "-f", "evt.is_open_write=true and fd.typechar='f' and fd.num>=0"]

parameters = [
    (
        {
            'sinsp': sinsp_container,
            'generator': generator_container
        },
        expected_arg
    )
    for (generator_container, expected_arg) in generator_tuples
    for sinsp_container in sinsp.generate_specs(args=sinsp_filters)
]


@pytest.mark.parametrize('run_containers,expected_arg', parameters, indirect=['run_containers'], ids=generate_ids(parameters))
def test_file_writes(run_containers, expected_arg):
    sinsp_container = run_containers['sinsp']
    generator_container = run_containers['generator']
    generator_container.wait()

    expected_events = [
        {
            "evt.args": SinspField.regex_field(expected_arg),
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": "<",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": SinspField.regex_field(r'^(?:open|openat|openat2)$'),
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        }
    ]

    assert_events(expected_events, sinsp_container)
