import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events

sinsp_filters = ["-f", "evt.type=setuid"]

containers = [
    {
        'sinsp': sinsp_container,
        'generator': event_generator.container_spec('syscall.NonSudoSetuid'),
    } for sinsp_container in sinsp.generate_specs(args=sinsp_filters)
]

ids = [
    f'{sinsp.generate_id(c["sinsp"])}-{event_generator.generate_id(c["generator"])}'
    for c in containers
]


@pytest.mark.parametrize("run_containers", containers, indirect=True, ids=ids)
def test_non_sudo_setuid(run_containers):
    sinsp_container = run_containers['sinsp']

    generator_container = run_containers['generator']
    generator_container.wait()

    expected_events = [
        {
            "evt.args": "uid=2(<NA>) ",
            "evt.dir": ">",
            "evt.type": "setuid",
            "proc.name": "child",
        },
        {
            "evt.args": "res=0 ",
            "evt.dir": "<",
            "evt.type": "setuid",
            "proc.name": "child",
        },
        {
            "evt.args": "uid=0(<NA>) ",
            "evt.dir": ">",
            "evt.type": "setuid",
            "proc.name": "child",
        },
        {
            "evt.args": "res=-1(EPERM) ",
            "evt.dir": "<",
            "evt.type": "setuid",
            "proc.name": "child",
        },
    ]

    assert_events(expected_events, sinsp_container)
