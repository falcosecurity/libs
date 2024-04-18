from datetime import datetime
from time import sleep
import os
import json
import docker
import re
from enum import Enum
from abc import ABC, abstractmethod
from subprocess import Popen
from queue import Queue
from threading import Thread
from typing import IO, AnyStr

from sinspqa import is_containerized, LOGS_PATH, BTF_IS_AVAILABLE

SINSP_TAG = os.environ.get('SINSP_TAG', 'latest')


class SinspStreamer(ABC):
    """
    Allows streaming of `sinsp-example` logs for analysis.
    """

    @abstractmethod
    def read(self):
        """
        Reads logs from a container and returns them as a generator.

        Returns:
            A string holding a single log line from the container.
        """
        pass


class SinspContainerStreamer(SinspStreamer):
    def __init__(self, container: docker.models.containers.Container, timeout: int = 10):
        """
        Parameters:
            container (docker.Container): A container object to stream logs from.
            timeout (int): The maximum amount of time the streamer will read logs from the container.
        """
        self.container = container
        self.timeout = timeout
        self.last_timestamp = None

    def read(self):
        start = datetime.now()

        while True:
            sleep(0.2)

            for raw_log in self.container.logs(stream=True,
                                               follow=False,
                                               timestamps=True,
                                               since=self.last_timestamp):
                self.last_timestamp, log = self.extract_log(raw_log)
                yield log

            if (datetime.now() - start).total_seconds() > self.timeout:
                break

    def extract_log(self, raw_log: str):
        """
        Split the docker log timestamp from the log line and return them

        The expected log needs to have the timestamp provided by docker,
        similar to running 'docker logs -t sinsp-example'

        Example log:
            2022-07-29T09:45:41.896041322Z {"evt.args":"","evt.cpu":0,"evt.dir":">","evt.num":18380,"evt.time":1659087941552081087,"evt.type":"epoll_pwait","proc.name":"<NA>","thread.tid":49892}
        Parameters:
            raw_log (binary): The log line as extracted from the logs call.

        Returns:
            A tuple holding a datetime object with the timestamp and a string with the log line.
        """
        decoded_log = raw_log.decode("utf-8").strip()
        split_log = decoded_log.split(" ")
        return datetime.strptime(split_log[0][:-4], "%Y-%m-%dT%H:%M:%S.%f"), " ".join(split_log[1:])


class SinspProcessStreamer(SinspStreamer):
    _running = True

    def __init__(self, process: Popen, timeout: int = 10):
        """
        Parameters:
            container (docker.Container): A container object to stream logs from.
            timeout (int): The maximum amount of time the streamer will read logs from the container.
        """
        self.process = process
        self.timeout = timeout
        self.queue = Queue()
        self.stdout_thread = Thread(target=SinspProcessStreamer._readline,
                                    args=[self.process.stdout, self.queue])
        SinspProcessStreamer._running = True
        self.stdout_thread.start()

    def stop(self):
        SinspProcessStreamer._running = False
        self.stdout_thread.join(timeout=1)

    @staticmethod
    def _readline(stream: IO[AnyStr], queue: Queue):
        with open(os.path.join(LOGS_PATH, 'sinsp.log'), 'a') as f:
            while SinspProcessStreamer._running:
                for line in iter(stream.readline, ''):
                    if line != '' and line != 'null':
                        f.write(line)
                        queue.put(line.rstrip())

    def read(self):
        start = datetime.now()

        while self.process.poll() is None:
            sleep(0.2)

            while not self.queue.empty():
                yield self.queue.get(block=False)

            if (datetime.now() - start).total_seconds() > self.timeout:
                break


class SinspStreamerBuilder:
    def __init__(self):
        self._timeout = 10
        self._sinsp = None
        self._container = False

    def build(self) -> SinspStreamer:
        if self._sinsp is None:
            raise "sinsp must be set"

        if self._container:
            return SinspContainerStreamer(self._sinsp, timeout=self._timeout)
        else:
            return SinspProcessStreamer(self._sinsp, timeout=self._timeout)

    def setContainerized(self, containerized: bool):
        self._container = containerized
        return self

    def setTimeout(self, timeout: int):
        self._timeout = timeout
        return self

    def setSinsp(self, sinsp: dict):
        self._sinsp = sinsp
        return self


class SinspFieldTypes(Enum):
    STRING = 0
    REGEX = 1


class SinspField:
    """
    Stores the value expected in a field output by sinsp-example.
    """

    def __init__(self, value, value_type=SinspFieldTypes.STRING):
        self.value_type = value_type

        if self.value_type == SinspFieldTypes.REGEX:
            self.value = re.compile(value)
        else:
            self.value = value

    def compare(self, other: str) -> bool:
        if self.value_type == SinspFieldTypes.REGEX:
            return self.value.match(other)

        return self.value == other

    def __repr__(self):
        if self.value_type == SinspFieldTypes.REGEX:
            return f"r'{self.value.pattern}'"
        else:
            return self.value

    def numeric_field():
        return SinspField(r'^\d+$', SinspFieldTypes.REGEX)

    def regex_field(regex: str):
        return SinspField(regex, SinspFieldTypes.REGEX)


def parse_log(log: str) -> dict:
    """
    Parses a log line from the `sinsp-example` binary.

    Parameters:
        log (str): A string holding a single log line from `sinsp-example``

    Returns:
        A dictionary holding all the captured values for the event.
    """
    if log.startswith('--'):
        # sinsp-example diagnostic messages
        print(log)
        return None
    try:
        return json.loads(log)
    except json.JSONDecodeError as e:
        print(f'Failed to parse JSON: {e}')
        print(log)
        return None


def validate_event(expected_fields: dict, event: dict) -> bool:
    """
    Checks all `expected_fields` are in the `event`

    Parameters:
        expected_fields (dict): A dictionary holding the values expected in the event.
        event (dict): A sinsp event parsed by calling `parse_log`

    Returns:
        True if all `expected_fields` are in the event and have matching values, False otherwise.
    """
    if event is None:
        return False

    for k in expected_fields:
        if k not in event:
            return False

        expected = expected_fields[k]

        if isinstance(expected, SinspField):
            if expected.compare(str(event[k])):
                continue
            return False

        if expected != event[k]:
            return False

    return True


def assert_events(expected_events: dict,
                  sinsp,
                  timeout: int = 10):
    """
    Takes a list of dictionaries describing the events we want to receive
    from a sinsp-example container and the reads events from the provided
    container handle until either all events are found or a timeout occurs.

    Parameters:
        expected_fields (dict): A dictionary holding the values expected in the event.
        container (docker.Container): A container object to stream logs from.
        timeout (int): The seconds to wait for the events to be asserted
    """
    for event in expected_events:
        success = False
        received_event = None

        for log in sinsp.read():
            if not log:
                continue

            received_event = parse_log(log)
            if validate_event(event, received_event):
                success = True
                break
        assert success, f"Did not receive expected event: {event}"


def sinsp_validation(container: docker.models.containers.Container) -> (bool, str):
    """
    Checks a container exited correctly
    """
    container.reload()
    exit_code = container.attrs['State']['ExitCode']

    assert exit_code == 0, f'container exited with code {exit_code}'


def container_spec(image: str = 'sinsp-example:latest', args: list = [], env: dict = {}) -> dict:
    """
    Generates a dictionary describing how to run the sinsp-example container

    Parameters:
        image (str): The name of the image used for running
        args (list): A list of arguments to supply into the container
    Returns:
        A dictionary describing how to run the sinsp-example container
    """
    mounts = [
        docker.types.Mount("/host/dev", "/dev", type="bind",
                           consistency="delegated", read_only=True),
        docker.types.Mount("/host/proc", "/proc", type="bind",
                           consistency="delegated", read_only=True),
    ]

    return {
        'image': image,
        'args': args,
        'mounts': mounts,
        'env': env,
        'privileged': True,
        'pid_mode': 'host',
        'network_mode': 'host',
        'init_wait': 2,
        'post_validation': sinsp_validation,
    }


def process_spec(path: str, args: list, env: dict) -> dict:
    return {
        'path': path,
        'args': args,
        'env': env,
        'init_wait': 2,
    }


def generate_specs(image: str = 'sinsp-example:latest',
                   path: str = os.environ.get('SINSP_EXAMPLE_PATH', ''),
                   args: list = []) -> list:
    """
    Generates a list of dictionaries describing how to run sinsp-example

    Parameters:
        image (str): The name of the image used for running
        path (str): The path to the sinsp-example binary
        args (list): A list of arguments to supply into the container
    Returns:
        A dictionary describing how to run the sinsp-example container
    """
    specs = []
    bpf_args = args.copy()
    bpf_args.extend([
        '-b', os.environ.get('BPF_PROBE'),
    ])
    modern_bpf_args = args.copy()
    modern_bpf_args.append('-m')

    kernel_module_env = {'KERNEL_MODULE': os.environ.get('KERNEL_MODULE', '')}
    bpf_env = {'BPF_PROBE': os.environ.get('BPF_PROBE', '')}

    if is_containerized():
        specs.append(container_spec(image, args, kernel_module_env))
        specs.append(container_spec(image, bpf_args, bpf_env))
        if BTF_IS_AVAILABLE:
            specs.append(container_spec(image, modern_bpf_args, {}))
    else:
        args.extend(['-j', '-a'])
        bpf_args.extend(['-j', '-a'])
        modern_bpf_args.extend(['-j', '-a'])

        specs.append(process_spec(path, args, kernel_module_env))
        specs.append(process_spec(path, bpf_args, bpf_env))
        if BTF_IS_AVAILABLE:
            specs.append(process_spec(path, modern_bpf_args, {}))

    return specs


def generate_id(spec: dict) -> str:
    env = spec['env']
    if 'BPF_PROBE' in env:
        return 'ebpf'
    elif 'KERNEL_MODULE' in env:
        return 'kmod'
    return 'modern_bpf'
