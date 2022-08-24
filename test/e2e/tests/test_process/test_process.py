import pytest
import subprocess
from sinspqa import sinsp
from sinspqa.sinsp import assert_events


sinsp_filters = ["-f", "evt.category=process and evt.type=execve"]
containers = [
    {
        'sinsp': sinsp_container
    } for sinsp_container in sinsp.generate_specs(args=sinsp_filters)
]
ids = [ sinsp.generate_id(c['sinsp']) for c in containers ]


@pytest.mark.parametrize("run_containers", containers, indirect=True, ids=ids)
def test_process(run_containers: dict, tester_id: str):
    """
    Runs a simple test where a bash script is executed and a corresponding sinsp event is found in the provided
    container's logs

    Parameters:
        sinsp (docker.Container): A detached container running the `sinsp-example` binary
    """
    sinsp_container = run_containers['sinsp']

    expected_events = [
        {
            'container.id': tester_id,
            'evt.category': 'process',
            'evt.type': 'execve',
            'proc.exe': 'cat',
            'proc.cmdline': 'cat /tmp/test.txt'
        }, {
            'container.id': tester_id,
            'evt.category': 'process',
            'evt.type': 'execve',
            'proc.exe': 'rm',
            'proc.cmdline': 'rm -f /tmp/test.txt'
        }
    ]

    subprocess.run("./test_sample.sh")

    assert_events(expected_events, sinsp_container)
