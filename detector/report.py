def print_module_result(result):
    print("\n" + "=" * 70)
    print(result["module"])
    print("=" * 70)

    print(f"Score   : {result['score']}")
    print(f"Passed  : {result['passed']}")
    print(f"Failed  : {result['failed']}")
    print(f"Skipped : {result['skipped']}")

    print("\nChecks")
    print("-" * 70)

    current_url = None

    for check in result["checks"]:

        if "url" in check and check["url"] != current_url:
            current_url = check["url"]
            print(f"\nURL: {current_url}")

        print(
            f"[{check['status']:^7}] "
            f"{check['name']:<20} "
            f"{check['details']}"
        )

    print("=" * 70)