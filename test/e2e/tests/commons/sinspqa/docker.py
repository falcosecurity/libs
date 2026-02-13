from docker.models.containers import Container


def get_container_id(container: Container) -> str:
    """
    Get the ID of the given container, truncated to 12 characters
    """
    return container.id[:12]


def get_network_data(container: Container) -> str:
    """
    Returns the first exposed port of the given container
    """
    container.reload()

    settings = container.attrs.get('NetworkSettings') or {}

    ip = settings.get('IPAddress')
    if not ip:
        networks = settings.get('Networks', {})
        for network_name, network_config in networks.items():
            if network_config.get('IPAddress'):
                ip = network_config['IPAddress']
                break


    # Try and get a single port number
    ports = settings.get('Ports') or {}
    ports = list(ports.keys())

    port = ports[0].split('/')[0] if len(ports) else None

    return f'{ip}:{port}' if port else ip
