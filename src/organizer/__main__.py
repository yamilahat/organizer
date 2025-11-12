import argparse

def main(argv=None):
    p = argparse.ArgumentParser(prog="organizer", description="Downloads organizer (MVP)")
    p.add_argument("--watch", help="Directory to watch", required=False)
    p.add_argument("--dry-run", action="store_true", help="Plan actions only")
    args = p.parse_args(argv)

    # stub behavior for now
    print(f"Organizer is alive. watch={args.watch!r} dry_run={args.dry_run}")

if __name__ == "__main__":
    main()