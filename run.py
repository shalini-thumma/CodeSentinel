import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parent


def main():
    load_dotenv(ROOT / ".env")
    api_host = os.getenv("CODESENTINEL_API_HOST", "127.0.0.1")
    api_port = os.getenv("CODESENTINEL_API_PORT", "8000")
    ui_host = os.getenv("CODESENTINEL_UI_HOST", "127.0.0.1")
    ui_port = os.getenv("CODESENTINEL_UI_PORT", "8501")
    environment = os.environ.copy()
    environment.setdefault("CODESENTINEL_API_URL", f"http://{api_host}:{api_port}")
    processes = []
    try:
        api = subprocess.Popen([
            sys.executable, "-m", "uvicorn", "codesentinel.main:app",
            "--host", api_host, "--port", api_port,
        ], cwd=ROOT, env=environment)
        processes.append(api)
        frontend = subprocess.Popen([
            sys.executable, "-m", "streamlit", "run", "frontend/app.py",
            "--server.address", ui_host, "--server.port", ui_port,
        ], cwd=ROOT, env=environment)
        processes.append(frontend)
        print(f"CodeSentinel dashboard: http://{ui_host}:{ui_port}")
        print(f"API health check: http://{api_host}:{api_port}/health")
        frontend.wait()
    except KeyboardInterrupt:
        pass
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            if process.poll() is None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()