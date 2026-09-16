import os
import subprocess
import socket
import base64
import time

def suspicious_strings():
    indicators = [
        "powershell -enc TEST_PAYLOAD",
        "cmd.exe /c suspicious_command",
        "CreateRemoteThread",
        "VirtualAlloc",
        "WriteProcessMemory",
        "regsvr32.exe",
        "rundll32.exe",
        "http://malicious-c2-server.test",
        "https://suspicious-download.test/payload",
        "download_and_execute",
        "persistence",
        "keylogger",
        "reverse_shell"
    ]

    print("=" * 60)
    print("THREATLENS SUSPICIOUS TEST FILE")
    print("=" * 60)

    print("\nSuspicious indicators contained in this file:\n")

    for item in indicators:
        print("[INDICATOR]", item)

    print("\nThis program does NOT execute any of the commands above.")
    print("They are included only as test strings for static analysis.")
    print("=" * 60)


def main():
    suspicious_strings()

    data = b"ThreatLens static malware analysis test"
    encoded = base64.b64encode(data)

    print("\nEncoded test data:", encoded.decode())
    print("Hostname:", socket.gethostname())
    print("Test completed safely.")


if __name__ == "__main__":
    main()