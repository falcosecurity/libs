import pytest
from sinspqa import sinsp
from sinspqa.sinsp import assert_events
from sinspqa.docker import get_container_id

sinsp_filters = ["-f", "evt.category=process and not container.id=host"]

containers = [
    {
        'sinsp': sinsp_container,
        'nginx': {
            'image': 'nginx:1.14-alpine',
        }
    } for sinsp_container in sinsp.generate_specs(args=sinsp_filters)
]

ids = [ sinsp.generate_id(c['sinsp']) for c in containers ]

@pytest.mark.parametrize("run_containers", containers, indirect=True, ids=ids)
def test_exec_in_container(run_containers: dict):
    nginx_container = run_containers['nginx']
    sinsp_container = run_containers['sinsp']

    container_id = get_container_id(nginx_container)

    nginx_container.exec_run("sleep 5")
    nginx_container.exec_run("sh -c ls")

    expected_events = [
        {
            'container.id': container_id,
            'evt.args': 'filename=/usr/sbin/nginx ',
            'evt.category': 'process',
            'evt.type': 'execve',
            'proc.exe': 'runc',
            'proc.cmdline': 'runc:[1:CHILD] init',
        }, {
            'container.id': container_id,
            'evt.category': 'process',
            'evt.type': 'execve',
            'proc.exe': 'nginx',
            'proc.cmdline': 'nginx -g daemon off;'
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
