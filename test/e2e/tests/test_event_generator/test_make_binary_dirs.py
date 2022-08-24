import pytest
from sinspqa import sinsp, event_generator
from sinspqa.sinsp import assert_events, SinspField

sinsp_filters = ["-f", "proc.name = event-generator"]
containers = [
    {
        'sinsp': sinsp_container,
        'generator': event_generator.container_spec('syscall.MkdirBinaryDirs'),
    } for sinsp_container in sinsp.generate_specs(args=sinsp_filters)
]

ids = [
    f'{sinsp.generate_id(c["sinsp"])}-{event_generator.generate_id(c["generator"])}'
    for c in containers
]


@pytest.mark.parametrize('run_containers', containers, indirect=True, ids=ids)
def test_make_binary_dirs(run_containers: dict):
    sinsp_container = run_containers['sinsp']
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

    assert_events(expected_events, sinsp_container)
