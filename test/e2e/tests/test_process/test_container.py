import pytest
from sinspqa import sinsp
from sinspqa.sinsp import assert_events
from sinspqa.docker import get_container_id

sinsp_args = [
    "-f", "evt.category=process and not container.id=host",
    "-o", "%container.id %evt.args %evt.category %evt.type %proc.cmdline %proc.exe %user.uid %user.name %user.homedir %group.gid %group.name"
]

containers = [
    {
        'sinsp': sinsp_container,
        'http-hello': {
            'image': 'hashicorp/http-echo:alpine',
            'args': ['-text=hello'],
            'user': '11:100'
        }
    } for sinsp_container in sinsp.generate_specs(args=sinsp_args)
]

ids = [ sinsp.generate_id(c['sinsp']) for c in containers ]

@pytest.mark.parametrize("run_containers", containers, indirect=True, ids=ids)
def test_exec_in_container(run_containers: dict):
    app_container = run_containers['http-hello']
    sinsp_container = run_containers['sinsp']

    container_id = get_container_id(app_container)

    app_container.exec_run("sleep 5")
    app_container.exec_run("sh -c ls")

    expected_events = [
        {
            'container.id': container_id,
            'evt.args': 'filename=/http-echo ',
            'evt.category': 'process',
            'evt.type': 'execve',
            'proc.exe': 'runc',
            'proc.cmdline': 'runc:[1:CHILD] init',
        }, {
            'container.id': container_id,
            'evt.category': 'process',
            'evt.type': 'execve',
            'proc.exe': '/http-echo',
            'proc.cmdline': 'http-echo -text=hello',
            'user.uid': 11,
            'user.name': 'operator',
            'group.gid': 100,
            'group.name': 'users',
        }, {
            'container.id': container_id,
            'evt.category': 'process',
            'evt.type': 'execve',
            'proc.exe': 'sleep',
            'proc.cmdline': 'sleep 5'
        }, {
            'container.id': container_id,
            'evt.category': 'process',
            'evt.type': 'execve',
            'proc.exe': 'sh',
            'proc.cmdline': 'sh -c ls'
        }
    ]

    assert_events(expected_events, sinsp_container)



containers = [
    {
        'sinsp': sinsp_container,
        'nginx': {
            'image': 'nginx:1.14-alpine',
        }
    } for sinsp_container in sinsp.generate_specs(args=sinsp_args)
]

ids = [ sinsp.generate_id(c['sinsp']) for c in containers ]

@pytest.mark.parametrize("run_containers", containers, indirect=True, ids=ids)
def test_container_root_user(run_containers: dict):
    app_container = run_containers['nginx']
    sinsp_container = run_containers['sinsp']

    container_id = get_container_id(app_container)

    app_container.exec_run("sh -c ls", user='nginx')

    expected_events = [
        {
            'container.id': get_container_id(run_containers['nginx']),
            'evt.category': 'process',
            'evt.type': 'execve',
            'proc.exe': 'nginx',
            'proc.cmdline': 'nginx -g daemon off;',
            'user.uid': 0,
            'user.name': 'root',
            'user.homedir': '/root',
            'group.gid': 0,
            'group.name': 'root'
        }, {
            'container.id': container_id,
            'evt.category': 'process',
            'evt.type': 'execve',
            'proc.exe': 'sh',
            'proc.cmdline': 'sh -c ls',
            'user.name': 'nginx',
            'group.name': 'nginx',
        }
    ]

    assert_events(expected_events, sinsp_container)
