import os
import tempfile

containerized = int(os.environ.get('CONTAINERIZED', 0))


def is_containerized() -> bool:
    return containerized != 0


if is_containerized():
    LOGS_PATH = '/logs'
else:
    LOGS_PATH = tempfile.mkdtemp()

SINSP_LOG_PATH = os.path.join(LOGS_PATH, 'sinsp.log')
