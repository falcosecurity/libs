import pytest
from sinspqa import sinsp, event_generator, BTF_IS_AVAILABLE
from sinspqa.sinsp import assert_events, SinspField
from sinspqa.docker import get_container_id

sinsp_filters = ["-f", "evt.category=process and not container.id=host"]

containers = [
    {
        'generator': event_generator.container_spec('syscall.DbProgramSpawnedProcess')
    }
]

sinsp_examples = [
    sinsp_example for sinsp_example in sinsp.generate_specs(args=sinsp_filters)
]
ids = [
    sinsp.generate_id(sinsp_example) for sinsp_example in sinsp_examples
]

@pytest.mark.parametrize('sinsp', sinsp_examples, indirect=True, ids=ids)
@pytest.mark.parametrize("run_containers", containers, indirect=True)
def test_db_program_spawned_process(sinsp, run_containers: dict):
    generator_container = run_containers['generator']

    generator_id = get_container_id(generator_container)
    generator_container.wait()

    expected_events = [
        {
            "container.id": generator_id,
            "evt.args": SinspField.regex_field(r'^res=\d+ exe=/tmp/falco-event-generator\d+/mysqld args=--loglevel\.info\.run\.\^helper.ExecLs\$\. tid=\d+\(mysqld\) pid=\d+\(mysqld\) ptid=\d+\(event-generator\) .* flags=\d+\([|A-Z_]+\) uid=0 gid=0 vtid=\d+ vpid=\d+'),
            "evt.category": "process",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "clone",
            "proc.cmdline": "mysqld --loglevel info run ^helper.ExecLs$",
            "proc.exe": SinspField.regex_field(r'/tmp/falco-event-generator\d+/mysqld'),
            "proc.pid": SinspField.numeric_field(),
            "proc.ppid": SinspField.numeric_field()
        },
        {
            "container.id": generator_id,
            "evt.args": "filename=/bin/ls ",
            "evt.category": "process",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "execve",
            "proc.cmdline": "mysqld --loglevel info run ^helper.ExecLs$",
            "proc.exe": SinspField.regex_field(r"/tmp/falco-event-generator\d+/mysqld"),
            "proc.pid": SinspField.numeric_field(),
            "proc.ppid": SinspField.numeric_field()
        },
        {
            "container.id": generator_id,
            "evt.args": SinspField.regex_field(r'^res=0 exe=/bin/ls args=NULL tid=\d+\(ls\) pid=\d+\(ls\) ptid=\d+\(mysqld\) .* tty=0 pgid=1\(systemd\) loginuid=-1\(\<NONE\>\) flags=1\(EXE_WRITABLE\) cap_inheritable=0'),
            "evt.category": "process",
            "evt.num": SinspField.numeric_field(),
            "evt.time": SinspField.numeric_field(),
            "evt.type": "execve",
            "proc.cmdline": "ls",
            "proc.exe": "/bin/ls",
            "proc.pid": SinspField.numeric_field(),
            "proc.ppid": SinspField.numeric_field()
        },
    ]

    assert_events(expected_events, sinsp)
