import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events

sinsp_filters = ["-f", "evt.type=setuid"]

containers = [{
    'sinsp': sinsp.container_spec(args=sinsp_filters),
    'generator': event_generator.container_spec('syscall.NonSudoSetuid'),
}]


@pytest.mark.parametrize("run_containers", containers, indirect=True)
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
