#!/usr/bin/env python3

import socketserver
import os
import re
import socket
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler


DELAY = 0.0
CONTAINER_JSON = '''{
  "Id": "CONTAINER_ID",
  "Created": "2019-01-14T16:42:46.980332855Z",
  "Path": "nginx",
  "Args": [
    "-g",
    "daemon off;"
  ],
  "State": {
    "Status": "running",
    "Running": true,
    "Paused": false,
    "Restarting": false,
    "OOMKilled": false,
    "Dead": false,
    "Pid": 6892,
    "ExitCode": 0,
    "Error": "",
    "StartedAt": "2019-07-04T15:14:21.106678691Z",
    "FinishedAt": "2019-06-24T14:45:06.735210924Z"
  },
  "Image": "sha256:568c4670fa800978e08e4a51132b995a54f8d5ae83ca133ef5546d092b864acf",
  "ResolvConfPath": "/var/lib/docker/containers/CONTAINER_ID/resolv.conf",
  "HostnamePath": "/var/lib/docker/containers/CONTAINER_ID/hostname",
  "HostsPath": "/var/lib/docker/containers/CONTAINER_ID/hosts",
  "LogPath": "/var/lib/docker/containers/CONTAINER_ID/CONTAINER_ID-json.log",
  "Name": "/nginx",
  "RestartCount": 0,
  "Driver": "overlay2",
  "Platform": "linux",
  "MountLabel": "",
  "ProcessLabel": "",
  "AppArmorProfile": "docker-default",
  "ExecIDs": null,
  "HostConfig": {
    "Binds": null,
    "ContainerIDFile": "",
    "LogConfig": {
      "Type": "json-file",
      "Config": {}
    },
    "NetworkMode": "default",
    "PortBindings": {},
    "RestartPolicy": {
      "Name": "no",
      "MaximumRetryCount": 0
    },
    "AutoRemove": false,
    "VolumeDriver": "",
    "VolumesFrom": null,
    "CapAdd": null,
    "CapDrop": null,
    "Dns": [],
    "DnsOptions": [],
    "DnsSearch": [],
    "ExtraHosts": null,
    "GroupAdd": null,
    "IpcMode": "shareable",
    "Cgroup": "",
    "Links": null,
    "OomScoreAdj": 0,
    "PidMode": "",
    "Privileged": false,
    "PublishAllPorts": false,
    "ReadonlyRootfs": false,
    "SecurityOpt": null,
    "UTSMode": "",
    "UsernsMode": "",
    "ShmSize": 67108864,
    "Runtime": "runc",
    "ConsoleSize": [
      0,
      0
    ],
    "Isolation": "",
    "CpuShares": 0,
    "Memory": 0,
    "NanoCpus": 1000000000,
    "CgroupParent": "",
    "BlkioWeight": 0,
    "BlkioWeightDevice": [],
    "BlkioDeviceReadBps": null,
    "BlkioDeviceWriteBps": null,
    "BlkioDeviceReadIOps": null,
    "BlkioDeviceWriteIOps": null,
    "CpuPeriod": 0,
    "CpuQuota": 0,
    "CpuRealtimePeriod": 0,
    "CpuRealtimeRuntime": 0,
    "CpusetCpus": "",
    "CpusetMems": "",
    "Devices": [],
    "DeviceCgroupRules": null,
    "DiskQuota": 0,
    "KernelMemory": 0,
    "MemoryReservation": 0,
    "MemorySwap": 0,
    "MemorySwappiness": null,
    "OomKillDisable": false,
    "PidsLimit": 0,
    "Ulimits": null,
    "CpuCount": 0,
    "CpuPercent": 0,
    "IOMaximumIOps": 0,
    "IOMaximumBandwidth": 0,
    "MaskedPaths": [
      "/proc/acpi",
      "/proc/kcore",
      "/proc/keys",
      "/proc/latency_stats",
      "/proc/timer_list",
      "/proc/timer_stats",
      "/proc/sched_debug",
      "/proc/scsi",
      "/sys/firmware"
    ],
    "ReadonlyPaths": [
      "/proc/asound",
      "/proc/bus",
      "/proc/fs",
      "/proc/irq",
      "/proc/sys",
      "/proc/sysrq-trigger"
    ]
  },
  "GraphDriver": {
    "Data": {
      "LowerDir": "/var/lib/docker/overlay2/5284854b193a34c17b13fb545c36dff28edce5643a93f19ad40147a667dd0f58-init/diff:/var/lib/docker/overlay2/19c870f9c69f36e320db5da254282fe84260abf1af9b85eab226450a0e74dfe5/diff:/var/lib/docker/overlay2/9ebfada4bda894ff1bc7e22c07d0590128f59e36abac32963372cf1faa50bd21/diff:/var/lib/docker/overlay2/172e9582199ef0bb9de43451eb95f0d1901625a18af7351e1909aca8d1a7cd37/diff",
      "MergedDir": "/var/lib/docker/overlay2/5284854b193a34c17b13fb545c36dff28edce5643a93f19ad40147a667dd0f58/merged",
      "UpperDir": "/var/lib/docker/overlay2/5284854b193a34c17b13fb545c36dff28edce5643a93f19ad40147a667dd0f58/diff",
      "WorkDir": "/var/lib/docker/overlay2/5284854b193a34c17b13fb545c36dff28edce5643a93f19ad40147a667dd0f58/work"
    },
    "Name": "overlay2"
  },
  "Mounts": [],
  "Config": {
    "Hostname": "7951fb549ab9",
    "Domainname": "",
    "User": "",
    "AttachStdin": false,
    "AttachStdout": true,
    "AttachStderr": true,
    "ExposedPorts": {
      "80/tcp": {}
    },
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "NGINX_VERSION=1.15.7-1~stretch",
      "NJS_VERSION=1.15.7.0.2.6-1~stretch"
    ],
    "Cmd": [
      "nginx",
      "-g",
      "daemon off;"
    ],
    "ArgsEscaped": true,
    "Image": "nginx",
    "Volumes": null,
    "WorkingDir": "",
    "Entrypoint": null,
    "OnBuild": null,
    "Labels": {
      "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>"
    },
    "StopSignal": "SIGTERM"
  },
  "NetworkSettings": {
    "Bridge": "",
    "SandboxID": "7ed54ba097dd40da1bfa11a7ab1add815f9289407037f0971c5b487c279a3da7",
    "HairpinMode": false,
    "LinkLocalIPv6Address": "",
    "LinkLocalIPv6PrefixLen": 0,
    "Ports": {
      "80/tcp": null
    },
    "SandboxKey": "/var/run/docker/netns/7ed54ba097dd",
    "SecondaryIPAddresses": null,
    "SecondaryIPv6Addresses": null,
    "EndpointID": "1316e3ef1748bc5dd0771fd2b2736cc9cbd612096b03685180a839f750bc17e7",
    "Gateway": "172.17.0.1",
    "GlobalIPv6Address": "",
    "GlobalIPv6PrefixLen": 0,
    "IPAddress": "172.17.0.2",
    "IPPrefixLen": 16,
    "IPv6Gateway": "",
    "MacAddress": "02:42:ac:11:00:02",
    "Networks": {
      "bridge": {
        "IPAMConfig": null,
        "Links": null,
        "Aliases": null,
        "NetworkID": "ed370a609b530f9c5560561d37fcec6a0d444ba2ed5e85d9bda66c8e36fbb210",
        "EndpointID": "1316e3ef1748bc5dd0771fd2b2736cc9cbd612096b03685180a839f750bc17e7",
        "Gateway": "172.17.0.1",
        "IPAddress": "172.17.0.2",
        "IPPrefixLen": 16,
        "IPv6Gateway": "",
        "GlobalIPv6Address": "",
        "GlobalIPv6PrefixLen": 0,
        "MacAddress": "02:42:ac:11:00:02",
        "DriverOpts": null
      }
    }
  }
}
'''

CONTAINER_REQUEST = re.compile('^(?:/v1.[0-9]*)?/containers/([0-9a-f]+)/json')

class FakeDockerHTTPHandler(BaseHTTPRequestHandler):

    def _send_response(self, resp):
        resp_bytes = resp.encode('utf-8')  # Convert to bytes
        self.send_header('Content-Length', len(resp_bytes))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(resp_bytes)

    def do_GET(self):
        matches = CONTAINER_REQUEST.match(self.path)
        if matches:
            if DELAY < 0:
                time.sleep(-DELAY)
                self.send_response(404)
                self._send_response('Not found\n')
            else:
                time.sleep(DELAY)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                resp = CONTAINER_JSON.replace('CONTAINER_ID', matches.group(1))
                self._send_response(resp)
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self._send_response('Not found\n')


class UnixHTTPServer(HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = 'localhost'
        self.server_port = 0

    def get_request(self):
        request, client_address = HTTPServer.get_request(self)
        return request, ['local', 0]


if __name__ == '__main__':
    try:
        DELAY = float(sys.argv[1])
    except Exception:
        pass

    try:
        socket_path = sys.argv[2]
    except Exception:
        socket_path = '/tmp/http.socket'

    try:
        os.unlink(socket_path)
    except Exception:
        pass

    server = UnixHTTPServer(socket_path, FakeDockerHTTPHandler)
    server.serve_forever()
