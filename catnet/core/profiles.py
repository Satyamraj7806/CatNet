scan_profiles = {
    "quick" :{
        "name" : "Quick Scan",
        "nmap_args" : ["-T4", "--top-ports", "100"]
    },
    "full" : {
        "name" : "Full Scan",
        "nmap_args" : ["-sS","-sV","-O", "-T4", "-p-"]
    },
    "deep" : {
        "name" : "Deep Scan",
        "nmap_args" : ["-sS", "-sV", "-O", "-A", "-T4", "-p-"]
    },
    "stealth" : {
        "name" : "Stealth Scan",
        "nmap_args" : ["-T2", "-sS"]
    }   
}