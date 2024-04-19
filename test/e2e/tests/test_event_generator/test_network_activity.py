import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events, SinspField
from sinspqa.docker import get_container_id

ipv4_regex = r'\d+\.\d+\.\d+\.\d+:\d+'

containers = [
    {
        'generator': event_generator.container_spec('syscall.SystemProcsNetworkActivity')
    }
]

sinsp_filters = ["-f", "evt.category=net and not container.id=host"]
sinsp_examples = [
    sinsp_example for sinsp_example in sinsp.generate_specs(args=sinsp_filters)
]
ids = [
    sinsp.generate_id(sinsp_example) for sinsp_example in sinsp_examples
]


@pytest.mark.parametrize('sinsp', sinsp_examples, indirect=True, ids=ids)
@pytest.mark.parametrize("run_containers", containers, indirect=True)
def test_network_activity(sinsp, run_containers: dict):
    generator_container = run_containers['generator']
    generator_id = get_container_id(generator_container)
    generator_container.wait()

    expected_events = [
        {
            "container.id": generator_id,
            "evt.args": "fd=3(<4>) addr=10.2.3.4:8192",
            "evt.category": "net",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "connect",
            "fd.name": "",
            "proc.cmdline": "sha1sum --loglevel info run ^helper.NetworkActivity$",
            "proc.exe": SinspField.regex_field(r'^/tmp/falco-event-generator\d+/sha1sum$'),
            "proc.pid": SinspField.numeric_field(),
            "proc.ppid": SinspField.numeric_field()
        },
        {
            "container.id": generator_id,
            "evt.args": SinspField.regex_field(fr'^res=0 tuple={ipv4_regex}->10\.2\.3\.4:8192 fd=3\(<4u>{ipv4_regex}->10\.2\.3\.4:8192\)$'),
            "evt.category": "net",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "connect",
            "fd.name": SinspField.regex_field(fr'^{ipv4_regex}->10\.2\.3\.4:8192$'),
            "proc.cmdline": "sha1sum --loglevel info run ^helper.NetworkActivity$",
            "proc.exe": SinspField.regex_field(r'^/tmp/falco-event-generator\d+/sha1sum$'),
            "proc.pid": SinspField.numeric_field(),
            "proc.ppid": SinspField.numeric_field()
        },
    ]

    assert_events(expected_events, sinsp)
