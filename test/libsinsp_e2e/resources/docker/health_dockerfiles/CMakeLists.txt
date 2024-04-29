foreach(
    dockerfile
    Dockerfile.healthcheck
    Dockerfile.healthcheck_shell
    Dockerfile.healthcheck_cmd_overlap
    Dockerfile.healthcheck_liveness
    Dockerfile.healthcheck_readiness
    Dockerfile.no_healthcheck
    Dockerfile.none_healthcheck
)

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/${dockerfile} ${CMAKE_CURRENT_BINARY_DIR}/${dockerfile}
        COPYONLY
    )

endforeach(dockerfile)
