import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events, SinspField

containers = [
    {
        'generator': event_generator.container_spec('syscall.MkdirBinaryDirs'),
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
def test_make_binary_dirs(sinsp, run_containers: dict):
    generator_container = run_containers['generator']
    generator_container.wait()

    expected_events = [
        {
            "evt.args": "",
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": ">",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "mkdirat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        },
        {
            "evt.args": "res=0 dirfd=-100(AT_FDCWD) path=/bin/directory-created-by-event-generator mode=1ED ",
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": "<",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "mkdirat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        },
        {
            "evt.args": "",
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": ">",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "unlinkat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        },
        {
            "evt.args": "res=-21(EISDIR) dirfd=-100(AT_FDCWD) name=/bin/directory-created-by-event-generator flags=0 ",
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": "<",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "unlinkat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        },
        {
            "evt.args": "",
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": ">",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "unlinkat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        },
        {
            "evt.args": "res=0 dirfd=-100(AT_FDCWD) name=/bin/directory-created-by-event-generator flags=512(AT_REMOVEDIR) ",
            "evt.cpu": SinspField.numeric_field(),
            "evt.dir": "<",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "unlinkat",
            "proc.name": "event-generator",
            "thread.tid": SinspField.numeric_field()
        },
    ]

    assert_events(expected_events, sinsp)
