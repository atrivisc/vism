import secrets
import string
import subprocess


def get_needed_libraries(binary_path) -> list[str]:
    command = f"ldd {binary_path} | grep -oP '\\s/([^\\s])*'"
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=True
    )

    return list(
        map(
            lambda x: x.strip(),
            result.stdout.split("\n")[:-1]
        )
    )

def generate_password(length: int = 16) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))