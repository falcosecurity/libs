def container_spec(syscall: str) -> dict:
    return {
        'image': 'falcosecurity/event-generator',
        'args': ['run', syscall, '--all'],
        'privileged': True,
    }


def generate_id(spec: dict) -> str:
    return spec['args'][1]
