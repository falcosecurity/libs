def container_spec(syscall):
    return {
        'image': 'falcosecurity/event-generator',
        'args': ['run', syscall],
        'privileged': True,
    }
