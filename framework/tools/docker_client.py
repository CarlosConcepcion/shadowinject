import os
import time
import tempfile
from typing import Optional
from framework.models.exploit import Exploit, ExploitResult


class DockerClient:
    def __init__(
        self,
        image: str = "python:3.11-slim",
        timeout: int = 30,
        network_disabled: bool = True,
        memory_limit: str = "256m",
        cpu_limit: float = 1.0,
    ):
        self.image = image
        self.timeout = timeout
        self.network_disabled = network_disabled
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit

    def is_available(self) -> bool:
        try:
            import docker
            client = docker.from_env()
            client.ping()
            return True
        except Exception:
            return False

    def execute_script(self, exploit: Exploit, script_path: str) -> ExploitResult:
        import docker
        client = docker.from_env()
        script_dir = os.path.dirname(os.path.abspath(script_path))
        script_name = os.path.basename(script_path)

        start = time.time()
        try:
            container = client.containers.run(
                image=self.image,
                command=["python", f"/app/{script_name}", "--target", "127.0.0.1"],
                volumes={script_dir: {"bind": "/app", "mode": "ro"}},
                working_dir="/app",
                network_disabled=self.network_disabled,
                mem_limit=self.memory_limit,
                nano_cpus=int(self.cpu_limit * 1e9),
                detach=True,
                auto_remove=False,
            )
            result = container.wait(timeout=self.timeout)
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            container.remove(force=True)

            elapsed = time.time() - start
            exit_code = result.get("StatusCode", -1)
            return ExploitResult(
                success=(exit_code == 0),
                output=logs if exit_code == 0 else None,
                error=logs if exit_code != 0 else None,
                execution_time=round(elapsed, 2),
            )
        except docker.errors.ContainerError as e:
            return ExploitResult(
                success=False,
                error=f"Container error: {e}",
                execution_time=round(time.time() - start, 2),
            )
        except docker.errors.ImageNotFound:
            return ExploitResult(
                success=False,
                error=f"Docker image '{self.image}' not found. Pull it first.",
            )
        except Exception as e:
            return ExploitResult(
                success=False,
                error=f"Execution error: {e}",
                execution_time=round(time.time() - start, 2),
            )

    @staticmethod
    def write_script(exploit: Exploit, output_dir: str = "exploits") -> str:
        os.makedirs(output_dir, exist_ok=True)
        vuln_type = exploit.vulnerability.vuln_type.value.lower().replace(" ", "_")
        filename = f"poc_{vuln_type}_{int(time.time())}.py"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(exploit.script_content)
        exploit.script_filename = filename
        return filepath
