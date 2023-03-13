import pytest
from sinspqa import sinsp, BTF_IS_AVAILABLE
from sinspqa.sinsp import assert_events
from sinspqa.docker import get_container_id, get_network_data

containers = [
    {
        'nginx': {
            'image': 'nginx:1.14-alpine',
        },
        'curl': {
            'image': 'pstauffer/curl:latest',
            'args': ["sleep", "300"]
        }
    }
]

sinsp_filters = ["-f", "evt.category=net and not container.id=host"]
sinsp_examples = [
    sinsp_example for sinsp_example in sinsp.generate_specs(args=sinsp_filters)
]
ids = [sinsp.generate_id(sinsp_example) for sinsp_example in sinsp_examples]

# For some reason, the modern probe gives a longer proc.exe than the legacy
# drivers, needs further investigation.
if BTF_IS_AVAILABLE:
    sinsp_examples[2] = pytest.param(
        sinsp_examples[2], marks=pytest.mark.xfail)


def expected_events(origin: dict, destination: dict) -> list:
    return [
        {
            "container.id": origin['id'],
            "evt.args": "domain=2(AF_INET) type=1 proto=0 ",
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
            "evt.type": "accept4",
            "fd.name": None,
            "proc.cmdline": "nginx",
            "proc.exe": "nginx: master proces",
        }, {
            "container.id": destination['id'],
            "evt.args": f"fd=3(<4t>{origin['ip']}->{destination['ip']}) tuple={origin['ip']}->{destination['ip']} queuepct=0 queuelen=0 queuemax=511 ",
            "evt.category": "net",
            "evt.type": "accept4",
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


@pytest.mark.parametrize('sinsp', sinsp_examples, indirect=True, ids=ids)
@pytest.mark.parametrize("run_containers", containers, indirect=True)
def test_curl_nginx(sinsp, run_containers: dict):
    # Use a specific local port so validation of events is easier
    local_port = 40000

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

    curl_container.exec_run(
        f'curl --local-port {local_port} {destination["ip"]}')

    assert_events(expected_events(origin, destination), sinsp)
