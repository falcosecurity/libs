import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events

containers = [
    {
        'generator': event_generator.container_spec('syscall.NonSudoSetuid'),
    }
]

sinsp_filters = ["-f", "evt.type=setuid", "-E"]
sinsp_examples = [
    sinsp_example for sinsp_example in sinsp.generate_specs(args=sinsp_filters)
]
ids = [
    sinsp.generate_id(sinsp_example) for sinsp_example in sinsp_examples
]


@pytest.mark.parametrize('sinsp', sinsp_examples, indirect=True, ids=ids)
@pytest.mark.parametrize("run_containers", containers, indirect=True)
def test_non_sudo_setuid(sinsp, run_containers):
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

    assert_events(expected_events, sinsp)
