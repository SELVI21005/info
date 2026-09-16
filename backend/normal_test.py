import math
import statistics
from datetime import datetime
import random

def calculate_statistics(numbers):
    return {
        "count": len(numbers),
        "mean": statistics.mean(numbers),
        "median": statistics.median(numbers),
        "maximum": max(numbers),
        "minimum": min(numbers),
        "standard_deviation": statistics.stdev(numbers)
    }

def main():
    numbers = [12, 18, 25, 31, 42, 56, 63, 71, 84, 95]

    print("=" * 50)
    print("NORMAL TEST APPLICATION")
    print("=" * 50)

    print("\nCurrent time:", datetime.now())
    print("Square root of 144:", math.sqrt(144))
    print("Random number:", random.randint(1, 100))

    print("\nStatistics:")
    result = calculate_statistics(numbers)

    for key, value in result.items():
        print(f"{key}: {value}")

    print("\nApplication completed successfully.")
    print("=" * 50)

if __name__ == "__main__":
    main()