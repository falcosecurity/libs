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


kernel = os.uname().release.split('.')
kernel_major = int(kernel[0])
kernel_minor = int(kernel[1])

BTF_IS_AVAILABLE = kernel_major > 5 or (
    kernel_major == 5 and kernel_minor >= 8)
