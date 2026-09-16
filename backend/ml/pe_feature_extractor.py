from pathlib import Path
import math

import numpy as np


# ============================================================
# CONSTANTS
# ============================================================

VECTOR_SIZE = 560


# ============================================================
# BASIC HELPERS
# ============================================================

def byte_histogram(data):
    """
    Create a 256-bin byte histogram.
    """

    histogram = [0.0] * 256

    for byte in data:
        histogram[byte] += 1.0

    total = len(data)

    if total > 0:
        histogram = [
            value / total
            for value in histogram
        ]

    return histogram


def entropy(data):
    """
    Calculate Shannon entropy.
    """

    if not data:
        return 0.0

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    length = len(data)

    result = 0.0

    for count in counts:

        if count == 0:
            continue

        probability = count / length

        result -= probability * math.log2(
            probability
        )

    return result


def byte_entropy_features(data):
    """
    Generate a 256-value byte distribution representation.
    """

    if not data:
        return [0.0] * 256

    # Split the file into 256 chunks and calculate
    # normalized entropy for each chunk.
    chunk_size = max(
        1,
        math.ceil(len(data) / 256)
    )

    result = []

    for index in range(256):

        start = index * chunk_size
        end = start + chunk_size

        chunk = data[start:end]

        if chunk:
            value = entropy(chunk) / 8.0
        else:
            value = 0.0

        result.append(value)

    return result


# ============================================================
# STRING FEATURES
# ============================================================

def string_features(data):
    """
    Generate fixed string-related numerical features.
    """

    ascii_strings = []

    current = []

    for byte in data:

        if 32 <= byte <= 126:

            current.append(chr(byte))

        else:

            if len(current) >= 4:
                ascii_strings.append(
                    "".join(current)
                )

            current = []

    if len(current) >= 4:
        ascii_strings.append(
            "".join(current)
        )

    if not ascii_strings:

        return [
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
        ]

    lengths = [
        len(value)
        for value in ascii_strings
    ]

    printable_count = sum(
        lengths
    )

    return [
        float(len(ascii_strings)),
        float(np.mean(lengths)),
        float(np.std(lengths)),
        float(min(lengths)),
        float(max(lengths)),
        float(printable_count),
    ]


# ============================================================
# RAW FILE FEATURES
# ============================================================

def extract_raw_features(file_path):
    """
    Convert a raw uploaded file into a deterministic
    560-dimensional feature vector.

    NOTE:
    This uses the same feature-vector size expected by
    the trained Random Forest. It is an application-side
    inference representation and should be validated
    against a representative validation set before being
    treated as production-grade EMBER inference.
    """

    file_path = Path(file_path)

    with open(
        file_path,
        "rb"
    ) as file:

        data = file.read()

    features = []

    # --------------------------------------------------------
    # 1. 256 byte histogram features
    # --------------------------------------------------------

    features.extend(
        byte_histogram(data)
    )

    # --------------------------------------------------------
    # 2. 256 byte entropy features
    # --------------------------------------------------------

    features.extend(
        byte_entropy_features(data)
    )

    # --------------------------------------------------------
    # 3. String features
    # --------------------------------------------------------

    features.extend(
        string_features(data)
    )

    # At this point:
    #
    # 256 + 256 + 6 = 518
    #
    # Need 42 additional deterministic file features.

    # --------------------------------------------------------
    # 4. File-level features
    # --------------------------------------------------------

    file_size = len(data)

    pe_offset = 0

    if len(data) >= 64 and data[:2] == b"MZ":

        pe_offset = int.from_bytes(
            data[60:64],
            byteorder="little",
            signed=False
        )

    is_mz = 1.0 if data[:2] == b"MZ" else 0.0

    is_pe = 0.0

    if (
        pe_offset > 0
        and pe_offset + 4 <= len(data)
        and data[pe_offset:pe_offset + 4] == b"PE\x00\x00"
    ):
        is_pe = 1.0

    features.extend([
        float(file_size),
        float(is_mz),
        float(is_pe),
        float(pe_offset),
    ])

    # --------------------------------------------------------
    # 5. Header-related values
    # --------------------------------------------------------

    if is_pe:

        header_start = pe_offset + 4

        # Machine
        machine = int.from_bytes(
            data[
                header_start:
                header_start + 2
            ],
            "little",
            signed=False
        )

        # Number of sections
        sections = int.from_bytes(
            data[
                header_start + 2:
                header_start + 4
            ],
            "little",
            signed=False
        )

        # Timestamp
        timestamp = int.from_bytes(
            data[
                header_start + 4:
                header_start + 8
            ],
            "little",
            signed=False
        )

        # Characteristics
        characteristics = int.from_bytes(
            data[
                header_start + 18:
                header_start + 20
            ],
            "little",
            signed=False
        )

        features.extend([
            float(machine),
            float(sections),
            float(timestamp),
            float(characteristics),
        ])

    else:

        features.extend(
            [0.0] * 4
        )

    # --------------------------------------------------------
    # 6. File byte statistics
    # --------------------------------------------------------

    if data:

        values = np.frombuffer(
            data,
            dtype=np.uint8
        )

        features.extend([
            float(np.mean(values)),
            float(np.std(values)),
            float(np.min(values)),
            float(np.max(values)),
            float(np.median(values)),
            float(np.percentile(values, 25)),
            float(np.percentile(values, 75)),
            float(np.sum(values)),
        ])

    else:

        features.extend(
            [0.0] * 8
        )

    # --------------------------------------------------------
    # 7. Common suspicious byte signatures
    # --------------------------------------------------------

    signatures = [
        b"powershell",
        b"cmd.exe",
        b"CreateRemoteThread",
        b"VirtualAlloc",
        b"WriteProcessMemory",
        b"WinExec",
        b"ShellExecute",
        b"URLDownloadToFile",
        b"InternetOpen",
        b"HttpOpenRequest",
        b"CreateProcess",
        b"VirtualProtect",
        b"LoadLibrary",
        b"GetProcAddress",
        b"rundll32",
        b"regsvr32",
    ]

    lower_data = data.lower()

    for signature in signatures:

        features.append(
            float(
                lower_data.count(
                    signature.lower()
                )
            )
        )

    # 16 signature values added.

    # --------------------------------------------------------
    # 8. Additional structural statistics
    # --------------------------------------------------------

    zero_count = data.count(
        b"\x00"
    )

    null_ratio = (
        zero_count / len(data)
        if data
        else 0.0
    )

    features.extend([
        float(null_ratio),
        float(len(data) % 2),
        float(len(data) % 4),
        float(len(data) % 8),
        float(len(data) % 16),
    ])

    # --------------------------------------------------------
    # 9. Ensure exactly 560 features
    # --------------------------------------------------------

    if len(features) < VECTOR_SIZE:

        features.extend(
            [0.0] * (
                VECTOR_SIZE - len(features)
            )
        )

    elif len(features) > VECTOR_SIZE:

        features = features[
            :VECTOR_SIZE
        ]

    return np.array(
        features,
        dtype=np.float32
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:

        print(
            "Usage:"
        )

        print(
            "python pe_feature_extractor.py <file>"
        )

        sys.exit(1)

    file_path = sys.argv[1]

    vector = extract_raw_features(
        file_path
    )

    print(
        "Feature extraction successful."
    )

    print(
        "Feature count:",
        len(vector)
    )

    print(
        "Feature shape:",
        vector.shape
    )