import pytest
import docker
import os
from time import sleep
from sinspqa import LOGS_PATH
from sinspqa.docker import get_container_id


@pytest.fixture(scope="session", autouse=True)
def docker_client():
    """
    Create a docker client to be used by the tests.

    Returns:
        A docker.DockerClient object created from the environment the tests run on.
    """
    return docker.from_env()


@pytest.fixture(scope="module")
def tester_id(docker_client: docker.client.DockerClient):
    """
    Get the truncated ID of the test runner.

    Returns:
        A 12 character string with the ID.
    """
    tester_container = docker_client.containers.get('sinsp-e2e-tester')

    return get_container_id(tester_container)


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


@pytest.fixture(scope="function")
def run_containers(request, docker_client: docker.client.DockerClient):
    """
    Runs containers, dumps their logs and cleans'em up
    """
    containers = {}
    post = {}

    for name, container in request.param.items():
        image = container['image']
        args = container.get('args', '')
        privileged = container.get('privileged', False)
        mounts = container.get('mounts', [])
        environment = container.get('env', {})
        additional_wait = container.get('init_wait', 0)
        post_validation = container.get('post_validation', None)
        stop_signal = container.get('signal', None)
        user = container.get('user', '')
        pid_mode = container.get('pid_mode', '')
        network_mode = container.get('network_mode', '')

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

        containers[name] = handle
        post[name] = {
            'validation': post_validation,
            'signal': stop_signal
        }

        try:
            wait_container_running(handle, additional_wait)
        except TimeoutError as e:
            print(f'{name} failed to start, the test will fail')

    yield containers

    success = True
    errors = []

    for name, container in containers.items():
        validation = post[name]['validation']
        stop_signal = post[name]['signal']

        if stop_signal:
            container.kill(stop_signal)

        # The stop command is issued regardless of the kill command to ensure
        # the container stops
        container.stop()

        logs = container.logs().decode('utf-8')
        if logs:
            with open(os.path.join(LOGS_PATH, f'{name}.log'), 'w') as f:
                f.write(logs)

        if validation:
            try:
                validation(container)
            except AssertionError as e:
                errors.append(f'{name}: {e}')
                success = False

        container.remove()

    assert success, '\n'.join(errors)


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
