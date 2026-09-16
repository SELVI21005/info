import numpy as np


def safe_number(value, default=0.0):
    """Convert a value to a numeric value safely."""
    if isinstance(value, bool):
        return float(value)

    if isinstance(value, (int, float)):
        return float(value)

    return float(default)


def extract_fixed_features(record):
    """
    Convert an EMBER JSON record into a fixed-length numeric vector.

    The representation uses selected numeric fields from the EMBER
    feature groups and guarantees the same number of features for
    every record.
    """

    features = []

    # ---------------------------------------------------------
    # 1. Histogram features - 256
    # ---------------------------------------------------------
    histogram = record.get("histogram", [])

    if isinstance(histogram, list):
        features.extend(
            [safe_number(x) for x in histogram[:256]]
        )

    features.extend([0.0] * (256 - len(features)))

    # ---------------------------------------------------------
    # 2. Byte entropy features - 256
    # ---------------------------------------------------------
    byteentropy = record.get("byteentropy", [])

    byte_features = []

    if isinstance(byteentropy, list):
        byte_features = [
            safe_number(x) for x in byteentropy[:256]
        ]

    byte_features.extend([0.0] * (256 - len(byte_features)))

    features.extend(byte_features)

    # ---------------------------------------------------------
    # 3. Strings features
    # ---------------------------------------------------------
    strings = record.get("strings", {})

    string_keys = [
        "numstrings",
        "avlength",
        "printabledist",
        "printables",
        "entropy",
        "paths",
    ]

    for key in string_keys:
        value = strings.get(key, 0)

        if isinstance(value, list):
            # Fixed summary statistics for lists
            numeric_values = [
                safe_number(x) for x in value
                if isinstance(x, (int, float))
            ]

            if numeric_values:
                features.append(float(np.mean(numeric_values)))
                features.append(float(np.std(numeric_values)))
                features.append(float(np.max(numeric_values)))
                features.append(float(np.min(numeric_values)))
            else:
                features.extend([0.0, 0.0, 0.0, 0.0])
        else:
            features.append(safe_number(value))

    # ---------------------------------------------------------
    # 4. General PE features
    # ---------------------------------------------------------
    general = record.get("general", {})

    general_keys = [
        "size",
        "vsize",
        "has_debug",
        "exports",
        "imports",
        "has_relocations",
        "has_resources",
        "has_signature",
        "has_tls",
        "symbols",
    ]

    for key in general_keys:
        features.append(
            safe_number(general.get(key, 0))
        )

    # ---------------------------------------------------------
    # 5. Header features
    # ---------------------------------------------------------
    header = record.get("header", {})

    header_keys = [
        "coff",
        "optional",
    ]

    for key in header_keys:
        value = header.get(key, {})

        if isinstance(value, dict):
            numeric_values = []

            for item in value.values():
                if isinstance(item, (int, float)):
                    numeric_values.append(float(item))

            # Fixed 10 summary values per subsection
            if numeric_values:
                features.extend([
                    float(np.mean(numeric_values)),
                    float(np.std(numeric_values)),
                    float(np.min(numeric_values)),
                    float(np.max(numeric_values)),
                    float(np.sum(numeric_values)),
                ])
            else:
                features.extend([0.0] * 5)

        else:
            features.append(safe_number(value))

    # ---------------------------------------------------------
    # 6. Section statistics
    # ---------------------------------------------------------
    section = record.get("section", {})

    if isinstance(section, dict):
        for key in [
            "entry",
            "sections",
            "sections_entropy",
            "sections_vsize",
            "sections_size",
            "sections_virt",
            "sections_rwx",
        ]:
            value = section.get(key, 0)

            if isinstance(value, list):
                numeric_values = [
                    safe_number(x)
                    for x in value
                    if isinstance(x, (int, float))
                ]

                if numeric_values:
                    features.extend([
                        float(np.mean(numeric_values)),
                        float(np.std(numeric_values)),
                        float(np.min(numeric_values)),
                        float(np.max(numeric_values)),
                    ])
                else:
                    features.extend([0.0] * 4)

            else:
                features.append(safe_number(value))

    # ---------------------------------------------------------
    # 7. Imports summary
    # ---------------------------------------------------------
    imports = record.get("imports", {})

    if isinstance(imports, dict):
        features.append(float(len(imports)))

        dll_count = 0
        function_count = 0

        for funcs in imports.values():
            dll_count += 1

            if isinstance(funcs, list):
                function_count += len(funcs)

        features.append(float(dll_count))
        features.append(float(function_count))

    else:
        features.extend([0.0, 0.0, 0.0])

    # ---------------------------------------------------------
    # 8. Exports
    # ---------------------------------------------------------
    exports = record.get("exports", [])

    if isinstance(exports, list):
        features.append(float(len(exports)))
    else:
        features.append(0.0)

    # ---------------------------------------------------------
    # 9. Data directories
    # ---------------------------------------------------------
    datadirectories = record.get("datadirectories", [])

    if isinstance(datadirectories, list):
        numeric_values = [
            safe_number(x)
            for x in datadirectories
            if isinstance(x, (int, float))
        ]

        features.append(float(len(datadirectories)))

        if numeric_values:
            features.extend([
                float(np.mean(numeric_values)),
                float(np.std(numeric_values)),
                float(np.min(numeric_values)),
                float(np.max(numeric_values)),
            ])
        else:
            features.extend([0.0] * 4)

    else:
        features.extend([0.0] * 5)

    return np.array(features, dtype=np.float32)


def get_label(record):
    return int(record["label"])


# -------------------------------------------------------------
# Test
# -------------------------------------------------------------
if __name__ == "__main__":

    from data_loader import load_sample

    samples = load_sample(20)

    vectors = [
        extract_fixed_features(record)
        for record in samples
    ]

    print("Samples tested:", len(vectors))

    print(
        "Feature lengths:",
        [len(vector) for vector in vectors]
    )

    print(
        "Unique feature lengths:",
        sorted(set(len(vector) for vector in vectors))
    )

    if len(set(len(vector) for vector in vectors)) == 1:
        print("SUCCESS: All feature vectors have the same length.")
    else:
        print("ERROR: Feature vectors still have different lengths.")