from discovery import run_discovery 


target = input("enter the target's ip address: ")
results = run_discovery("discovery_output", target)


if results["error"]:
    print(f"Error: {results['error']}")
else:
    for host in results["hosts"]:
        print(host)
