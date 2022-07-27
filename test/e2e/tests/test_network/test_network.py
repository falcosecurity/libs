import pytest
from sinspqa import sinsp
from sinspqa.sinsp import assert_events
from sinspqa.docker import get_container_id, get_network_data

sinsp_filters = ["-f", "evt.category=net and not container.id=host"]

containers = [{
    'sinsp': sinsp.container_spec(args=sinsp_filters),
    'nginx': {
        'image': 'nginx:1.14-alpine',
    },
    'curl': {
        'image': 'pstauffer/curl:latest',
        'args': ["sleep", "300"]
    }
}]


def expected_events(origin: dict, destination: dict) -> list:
    return [
        {
            "container.id": origin['id'],
            "evt.args": "domain=2 type=1 proto=0 ",
            "evt.category": "net",
            "evt.type": "socket",
            "fd.name": None,
            "proc.cmdline": f"curl --local-port {origin['local_port']} {destination['ip']}",
            "proc.exe": "curl",
        }, {
            "container.id": origin['id'],
            "evt.args": "fd=3(<4>) ",
            "evt.category": "net",
            "evt.type": "socket",
            "fd.name": "",
            "proc.cmdline": f"curl --local-port {origin['local_port']} {destination['ip']}",
            "proc.exe": "curl",
        }, {
            "container.id": origin['id'],
            "evt.args": f"fd=3(<4t>0.0.0.0:{origin['local_port']}) addr={destination['ip']} ",
            "evt.category": "net",
            "evt.type": "connect",
            "fd.name": f"0.0.0.0:{origin['local_port']}",
            "proc.cmdline": f"curl --local-port {origin['local_port']} {destination['ip']}",
            "proc.exe": "curl",
        }, {
            "container.id": destination['id'],
            "evt.args": "flags=0 ",
            "evt.category": "net",
            "evt.type": "accept",
            "fd.name": None,
            "proc.cmdline": "nginx",
            "proc.exe": "nginx: master proces",
        }, {
            "container.id": destination['id'],
            "evt.args": f"fd=3(<4t>{origin['ip']}->{destination['ip']}) tuple={origin['ip']}->{destination['ip']} queuepct=0 queuelen=0 queuemax=511 ",
            "evt.category": "net",
            "evt.type": "accept",
            "fd.name": f"{origin['ip']}->{destination['ip']}",
            "proc.cmdline": "nginx",
            "proc.exe": "nginx: master proces",
        }, {
            "evt.args": f"fd=3(<4t>{origin['ip']}->{destination['ip']}) ",
            "evt.dir": ">",
            "evt.type": "close",
            "proc.name": "curl",
        }, {
            "evt.args": "res=0 ",
            "evt.dir": "<",
            "evt.type": "close",
            "proc.name": "curl",
        }, {
            "evt.args": f"fd=3(<4t>{origin['ip']}->{destination['ip']}) ",
            "evt.dir": ">",
            "evt.type": "close",
            "proc.name": "nginx",
        }, {
            "evt.args": "res=0 ",
            "evt.dir": "<",
            "evt.type": "close",
            "proc.name": "nginx",
        }
    ]


@pytest.mark.parametrize("run_containers", containers, indirect=True)
def test_curl_nginx(run_containers):
    # Use a specific local port so validation of events is easier
    local_port = 40000

    sinsp_container = run_containers['sinsp']
    nginx_container = run_containers['nginx']
    curl_container = run_containers['curl']

    destination = {
        'id': get_container_id(nginx_container),
        'ip': get_network_data(nginx_container)
    }
    origin = {
        'id': get_container_id(curl_container),
        'ip': f'{get_network_data(curl_container)}:{local_port}',
        'local_port': local_port
    }

    curl_container.exec_run(f'curl --local-port {local_port} {destination["ip"]}')

    assert_events(expected_events(origin, destination), sinsp_container)
