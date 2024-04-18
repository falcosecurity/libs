import pytest
import docker
import os
from time import sleep
from subprocess import Popen, PIPE

from sinspqa import LOGS_PATH, is_containerized
from sinspqa.sinsp import SinspStreamerBuilder


def pytest_addoption(parser):
    parser.addoption('--no-kmod', action='store_true',
                     default=False, help='Skip tests with kernel module')
    parser.addoption('--no-ebpf', action='store_true',
                     default=False, help='Skip tests with eBPF')
    parser.addoption('--no-modern', action='store_true',
                     default=False, help='Skip tests with modern eBPF')


def pytest_collection_modifyitems(config, items):
    no_kmod = config.getoption('--no-kmod')
    no_ebpf = config.getoption('--no-ebpf')
    no_modern = config.getoption('--no-modern')

    if not no_kmod and not no_ebpf and not no_modern:
        # We are not skipping any tests
        return

    skip_kmod = pytest.mark.skip(
        reason='Skipping tests with kernel module driver')
    skip_ebpf = pytest.mark.skip(reason='Skipping tests with eBPF driver')
    skip_modern = pytest.mark.skip(
        reason='Skipping tests with modern eBPF driver')

    for item in items:
        if no_kmod:
            for kw in item.keywords:
                if 'kmod' in kw:
                    item.add_marker(skip_kmod)
                    break
        if no_ebpf:
            for kw in item.keywords:
                if 'ebpf' in kw:
                    item.add_marker(skip_ebpf)
                    break
        if no_modern:
            for kw in item.keywords:
                if 'modern_bpf' in kw:
                    item.add_marker(skip_modern)
                    break


@pytest.fixture(scope="session", autouse=True)
def check_root():
    assert os.geteuid() == 0, 'e2e tests need to be run as root'


@pytest.fixture(scope="session", autouse=True)
def docker_client():
    """
    Create a docker client to be used by the tests.

    Returns:
        A docker.DockerClient object created from the environment the tests run on.
    """
    return docker.from_env()


def wait_container_running(container: docker.models.containers.Container, additional_wait: int = 0, retries: int = 5):
    success = False

    for _ in range(retries):
        container.reload()

        if container.status == 'running':
            success = True
            break

        sleep(0.5)

    if not success:
        raise TimeoutError

    if additional_wait:
        sleep(additional_wait)


def run_container(docker_client: docker.client.DockerClient, name: str, container: dict):
    image = container['image']
    args = container.get('args', '')
    privileged = container.get('privileged', False)
    mounts = container.get('mounts', [])
    environment = container.get('env', {})
    user = container.get('user', '')
    pid_mode = container.get('pid_mode', '')
    network_mode = container.get('network_mode', '')

    additional_wait = container.get('init_wait', 0)
    post_validation = container.get('post_validation', None)
    stop_signal = container.get('signal', None)

    handle = docker_client.containers.run(
        image,
        args,
        name=name,
        detach=True,
        privileged=privileged,
        mounts=mounts,
        environment=environment,
        user=user,
        pid_mode=pid_mode,
        network_mode=network_mode,
    )

    post = {
        'validation': post_validation,
        'signal': stop_signal
    }

    try:
        wait_container_running(handle, additional_wait)
    except TimeoutError:
        print(f'{name} failed to start, the test will fail')

    return (handle, post)


def teardown_container(name, container, validation, stop_signal):
    if stop_signal:
        container.kill(stop_signal)

    # The stop command is issued regardless of the kill command to ensure
    # the container stops
    container.stop()

    logs = container.logs().decode('utf-8')
    if logs:
        with open(os.path.join(LOGS_PATH, f'{name}.log'), 'w') as f:
            f.write(logs)

    result = ''
    if validation:
        try:
            validation(container)
        except AssertionError as e:
            result = f'{name}: {e}'

    container.remove()
    return result


@pytest.fixture(scope="function")
def run_containers(request, docker_client: docker.client.DockerClient):
    """
    Runs containers, dumps their logs and cleans'em up
    """
    containers = {}
    post = {}

    for name, container in request.param.items():
        handle, post_validation = run_container(docker_client, name, container)

        containers[name] = handle
        post[name] = post_validation

    yield containers

    success = True
    errors = []

    for name, container in containers.items():
        validation = post[name]['validation']
        stop_signal = post[name]['signal']

        result = teardown_container(name, container, validation, stop_signal)

        if result != '':
            errors.append(result)
            success = False

    assert success, '\n'.join(errors)


@pytest.fixture(scope='function')
def sinsp(request, docker_client: docker.client.DockerClient):
    """
    Runs an instance of sinsp-example, either in a container or as a regular
    process
    """
    if is_containerized():
        container = request.param
        handle, post = run_container(docker_client, 'sinsp', container)

        yield SinspStreamerBuilder() \
            .setContainerized(True) \
            .setSinsp(handle) \
            .setTimeout(10) \
            .build()

        validation = container.get('post_validation', None)
        stop_signal = container.get('signal', None)

        result = teardown_container(
            'sinsp', handle, validation, stop_signal)
        assert result == '', result

    else:
        process = request.param
        args = process['args']
        args.insert(0, process['path'])
        env = os.environ.copy()
        additional_wait = process.get('init_wait', 0)
        for k, v in process['env'].items():
            env[k] = v
        process = Popen(args, env=env, stdout=PIPE, universal_newlines=True)

        if additional_wait:
            sleep(additional_wait)

        reader = SinspStreamerBuilder() \
            .setContainerized(False) \
            .setSinsp(process) \
            .setTimeout(10) \
            .build()

        yield reader

        reader.stop()
        process.terminate()
        process.wait()
        assert process.returncode == 0, f'sinsp-example terminated with code {process.returncode}'


def pytest_html_report_title(report):
    report.title = "sinsp e2e tests"


def dump_logs(pytest_html, extra):
    """
    Finds all logs dumped to LOGS_PATH and makes them available through the
    auto-generated report
    """
    for file in os.listdir(LOGS_PATH):
        full_path = os.path.join(LOGS_PATH, file)
        if not os.path.isfile(full_path):
            continue

        with open(full_path, 'r', errors='replace') as f:
            logs = f.read()
            extra.append(pytest_html.extras.text(logs, name=file))

        # Remove file so it doesn't bleed to following tests
        os.remove(full_path)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    pytest_html = item.config.pluginmanager.getplugin("html")
    outcome = yield
    report = outcome.get_result()
    extra = getattr(report, "extra", [])

    if report.when == "teardown":
        dump_logs(pytest_html, extra)

    report.extra = extra
