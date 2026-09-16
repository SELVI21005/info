import hashlib
import mimetypes
import os
import re
from pathlib import Path

from services.yara_service import scan_file

try:
    import pefile
except ImportError:
    pefile = None


SUSPICIOUS_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
    "schtasks",
    "CreateRemoteThread",
    "VirtualAlloc",
    "WriteProcessMemory",
    "WinExec",
    "ShellExecute",
    "DownloadString",
    "Invoke-Expression",
    "base64",
    "download",
    "payload",
    "reverse shell",
]


def calculate_hashes(file_path: str):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            md5.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def identify_file(file_path: str):
    path = Path(file_path)

    mime_type, _ = mimetypes.guess_type(path.name)

    extension = path.suffix.lower()

    if extension:
        file_type = extension.replace(".", "").upper()
    else:
        file_type = "Unknown"

    return {
        "extension": extension or None,
        "file_type": file_type,
        "mime_type": mime_type or "application/octet-stream",
    }


def extract_metadata(file_path: str):
    path = Path(file_path)

    stat = path.stat()

    return {
        "filename": path.name,
        "extension": path.suffix.lower() or None,
        "size_bytes": stat.st_size,
        "created_time": stat.st_ctime,
        "modified_time": stat.st_mtime,
    }


def extract_strings(file_path: str):
    strings = []

    with open(file_path, "rb") as file:
        data = file.read()

    ascii_strings = re.findall(rb"[ -~]{4,}", data)

    for value in ascii_strings:
        try:
            decoded = value.decode(
                "ascii",
                errors="ignore"
            )

            if decoded:
                strings.append(decoded)

        except Exception:
            pass

    unicode_strings = re.findall(
        rb"(?:[\x20-\x7e]\x00){4,}",
        data,
    )

    for value in unicode_strings:
        try:
            decoded = value.decode(
                "utf-16le",
                errors="ignore"
            )

            if decoded:
                strings.append(decoded)

        except Exception:
            pass

    return list(dict.fromkeys(strings))


def extract_urls(strings):
    urls = []

    pattern = r"https?://[^\s\"'<>]+"

    for string in strings:
        matches = re.findall(
            pattern,
            string,
            re.IGNORECASE
        )

        urls.extend(matches)

    return list(dict.fromkeys(urls))


def extract_ips(strings):
    ips = []

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    for string in strings:
        matches = re.findall(pattern, string)

        for ip in matches:
            parts = ip.split(".")

            if all(
                0 <= int(part) <= 255
                for part in parts
            ):
                ips.append(ip)

    return list(dict.fromkeys(ips))


def find_suspicious_keywords(strings):
    matches = []

    combined_text = "\n".join(strings).lower()

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword.lower() in combined_text:
            matches.append(keyword)

    return matches


def analyze_pe(file_path: str):
    result = {
        "is_pe": False,
        "machine": None,
        "number_of_sections": None,
        "entry_point": None,
        "image_base": None,
        "subsystem": None,
        "dll_characteristics": None,
        "imports": [],
    }

    if pefile is None:
        return result

    try:
        pe = pefile.PE(
            file_path,
            fast_load=False
        )

        result["is_pe"] = True

        result["machine"] = hex(
            pe.FILE_HEADER.Machine
        )

        result["number_of_sections"] = (
            pe.FILE_HEADER.NumberOfSections
        )

        result["entry_point"] = hex(
            pe.OPTIONAL_HEADER.AddressOfEntryPoint
        )

        result["image_base"] = hex(
            pe.OPTIONAL_HEADER.ImageBase
        )

        result["subsystem"] = (
            pe.OPTIONAL_HEADER.Subsystem
        )

        result["dll_characteristics"] = hex(
            pe.OPTIONAL_HEADER.DllCharacteristics
        )

        if hasattr(
            pe,
            "DIRECTORY_ENTRY_IMPORT"
        ):

            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                dll_name = (
                    entry.dll.decode(
                        errors="ignore"
                    )
                    if entry.dll
                    else ""
                )

                for imported in entry.imports:

                    function_name = (
                        imported.name.decode(
                            errors="ignore"
                        )
                        if imported.name
                        else "ordinal"
                    )

                    result["imports"].append(
                        f"{dll_name}!{function_name}"
                    )

        pe.close()

    except Exception:
        pass

    return result


def analyze_import_indicators(pe_info):
    suspicious_imports = [
        "CreateRemoteThread",
        "VirtualAlloc",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateProcessA",
        "CreateProcessW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
    ]

    found = []

    imports_text = " ".join(
        pe_info.get("imports", [])
    ).lower()

    for indicator in suspicious_imports:

        if indicator.lower() in imports_text:
            found.append(indicator)

    return found


def calculate_static_risk(
    suspicious_keywords,
    urls,
    ips,
    pe_info,
    suspicious_imports,
    yara_match_count=0,
):
    score = 0

    # Suspicious strings / commands
    score += min(
        len(suspicious_keywords) * 8,
        40
    )

    # Network indicators
    score += min(
        len(urls) * 5,
        20
    )

    score += min(
        len(ips) * 5,
        15
    )

    # PE executable
    if pe_info["is_pe"]:
        score += 5

    # Suspicious Windows APIs
    score += min(
        len(suspicious_imports) * 10,
        30
    )

    # Add one controlled contribution per unique YARA rule match.
    score += min(
        yara_match_count * 15,
        100
    )

    return min(score, 100)


def analyze_file(file_path: str):

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            "File does not exist"
        )

    hashes = calculate_hashes(file_path)

    file_size = os.path.getsize(file_path)

    file_identification = identify_file(
        file_path
    )

    metadata = extract_metadata(
        file_path
    )

    strings = extract_strings(
        file_path
    )

    urls = extract_urls(
        strings
    )

    ips = extract_ips(
        strings
    )

    suspicious_keywords = (
        find_suspicious_keywords(strings)
    )

    pe_info = analyze_pe(
        file_path
    )

    suspicious_imports = (
        analyze_import_indicators(
            pe_info
        )
    )

    yara_analysis = scan_file(file_path)

    static_risk_score = calculate_static_risk(
        suspicious_keywords,
        urls,
        ips,
        pe_info,
        suspicious_imports,
        yara_analysis["match_count"],
    )

    if static_risk_score >= 70:

        classification = "Malicious"

    elif static_risk_score >= 30:

        classification = "Suspicious"

    else:

        classification = "Likely Benign"

    return {
        "filename": path.name,

        "file_size": file_size,

        "file_identification": file_identification,

        "metadata": metadata,

        "md5": hashes["md5"],

        "sha256": hashes["sha256"],

        "strings_count": len(strings),

        "urls": urls,

        "ips": ips,

        "suspicious_keywords": suspicious_keywords,

        "suspicious_imports": suspicious_imports,

        "yara_analysis": yara_analysis,

        "pe_analysis": pe_info,

        "static_risk_score": static_risk_score,

        "static_classification": classification,
    }