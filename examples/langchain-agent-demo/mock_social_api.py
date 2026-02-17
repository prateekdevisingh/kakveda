def post(content: str, platform: str) -> None:
    label = platform.capitalize()
    print(f"[MOCK POST SUCCESS] Platform: {label}")
    print("Content:")
    print(content)
