from __future__ import annotations

from pprint import pprint

from app.service import classify_url


def main() -> None:
    try:
        url = input("Enter a URL: ").strip()
    except EOFError:
        print("No input provided.")
        return

    if not url:
        print("URL must not be empty.")
        return

    try:
        result = classify_url(url)
    except ValueError as exc:
        print(f"Invalid URL: {exc}")
        return
    except Exception as exc:  # pragma: no cover - interactive helper
        print(f"Failed to classify URL: {exc}")
        return

    pprint(result)


if __name__ == "__main__":
    main()