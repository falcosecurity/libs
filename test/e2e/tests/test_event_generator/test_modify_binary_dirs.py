import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events, SinspField

containers = [
    {
        'generator': event_generator.container_spec('syscall.ModifyBinaryDirs'),
    }
]

sinsp_filters = ["-f", "proc.name = event-generator"]
sinsp_examples = [
    sinsp_example for sinsp_example in sinsp.generate_specs(args=sinsp_filters)
]
ids = [
    sinsp.generate_id(sinsp_example) for sinsp_example in sinsp_examples
]


@pytest.mark.parametrize('sinsp', sinsp_examples, indirect=True, ids=ids)
@pytest.mark.parametrize('run_containers', containers, indirect=True)
def test_modify_binary_dirs(sinsp, run_containers: dict):
    generator_container = run_containers['generator']
    generator_container.wait()

    expected_events = [
        {
            "evt.args": "",
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": ">",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "renameat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        },
        {
            "evt.args": "res=0 olddirfd=-100(AT_FDCWD) oldpath=/bin/true newdirfd=-100(AT_FDCWD) newpath=/bin/true.event-generator ",
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": "<",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "renameat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        },
        {
            "evt.args": "",
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": ">",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "renameat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        },
        {
            "evt.args": "res=0 olddirfd=-100(AT_FDCWD) oldpath=/bin/true.event-generator newdirfd=-100(AT_FDCWD) newpath=/bin/true ",
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": "<",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "renameat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        },
    ]

    assert_events(expected_events, sinsp)
