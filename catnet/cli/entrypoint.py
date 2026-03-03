import argparse


from catnet.orchestrator.orchestrator import run_pipeline

def main():
    parser = argparse.ArgumentParser(
        description= "CatNet- A modular and extensible network reconnaissance framework"
    )

    parser.add_argument(
        "-t", "--target", required=True, help="Target IP address or hostname"
    )
    args = parser.parse_args()
    run_pipeline(args.target)

if __name__ == "__main__":
    main()