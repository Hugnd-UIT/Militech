import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace


class Sandbox:

    def __init__(self, name=None):
        self.name = name or os.environ.get("CONTAINER_NAME", os.environ.get("CONTAINER_NAMEE", os.environ.get("HOSTNAME", "militech")))
        self.status = "running"

    def exec_run(self, cmd, stdout=True, stderr=True):
        if isinstance(cmd, str):
            args = ["/bin/bash", "-c", cmd]
        else:
            args = list(cmd)
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return SimpleNamespace(exit_code=proc.returncode, output=proc.stdout or b"")


def _docker_client():
    if "docker" in sys.modules and not hasattr(sys.modules["docker"], "from_env"):
        del sys.modules["docker"]

    if sys.path and sys.path[0] in ("", ".", os.getcwd()):
        _cwd = sys.path.pop(0)
        import docker
        sys.path.insert(0, _cwd)
    else:
        import docker
    return docker.from_env()


def init(repo_path=None, outputs_path="outputs"):
    client = _docker_client()

    repo_name = Path(repo_path).resolve().name if repo_path else "target"
    slug = repo_name.lower().replace("_", "-")
    sandbox_name = os.environ.get("CONTAINER_NAME", os.environ.get("CONTAINER_NAMEE", f"militech-{slug}"))

    volumes = {}
    if outputs_path:
        out_dir = Path(outputs_path).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        volumes[str(out_dir)] = {'bind': '/outputs', 'mode': 'rw'}
    if repo_path:
        repo_dir = Path(repo_path).resolve()
        if repo_dir.exists():
            volumes[str(repo_dir)] = {'bind': '/data', 'mode': 'rw'}

    root_dir = Path(__file__).resolve().parent.parent
    cfg_file = root_dir / "config" / "config.yml"
    if cfg_file.exists():
        volumes[str(cfg_file)] = {'bind': '/app/config/config.yml', 'mode': 'ro'}

    found = client.containers.list(filters={'name': sandbox_name}, all=True)

    if found:
        container = found[0]
        binds = container.attrs.get('HostConfig', {}).get('Binds') or []
        has_all = all(
            any(str(Path(host_p)).lower() in b.lower() and v['bind'] in b for b in binds)
            for host_p, v in volumes.items()
        )
        if volumes and not has_all:
            try:
                container.stop()
            except Exception:
                pass
            try:
                container.remove()
            except Exception:
                pass
            found = []

    if not found:
        # Check or build image
        image = "militech:latest"
        try:
            client.images.get(image)
        except Exception:
            dockerfile = root_dir / "docker" / "Dockerfile"
            if dockerfile.exists():
                client.images.build(path=str(root_dir), dockerfile="docker/Dockerfile", tag=image, rm=True)
            elif (root_dir / "Dockerfile").exists():
                client.images.build(path=str(root_dir), tag=image, rm=True)
            else:
                client.images.pull("kalilinux/kali-rolling")
                image = "kalilinux/kali-rolling"

        container = client.containers.run(
            image,
            entrypoint="/bin/bash",
            detach=True,
            tty=True,
            name=sandbox_name,
            cap_add=['NET_ADMIN', 'SYS_PTRACE'],
            devices=["/dev/net/tun"],
            environment={
                "DEBIAN_FRONTEND": "noninteractive",
                "CONTAINER_NAME": sandbox_name,
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": "/app",
            },
            volumes=volumes,
            stdin_open=True
        )

        if image == "kalilinux/kali-rolling":
            commands = (
                'apt update && '
                'apt -y install curl'
            )
            container.exec_run(f'/bin/bash -c "{commands}"', stdout=True, stderr=True)

        container.stop()

    if container.status != 'running':
        container.start()
        container.reload()

        # Start TUN if needed
        container.exec_run('/bin/bash -c "mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun"')

        # Start VPN if .ovpn exists
        container.exec_run('bash -c "compgen -G /data/*.ovpn > /dev/null && openvpn /data/*.ovpn"', detach=True)
        time.sleep(3)

    return container


if __name__ == '__main__':
    container = init()
    print(f"Container '{container.name}' is {container.status}")