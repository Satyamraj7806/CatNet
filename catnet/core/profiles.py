scan_profiles = {
    "quick" :{
        "name" : "Quick Scan",
        "nmap_args" : ["-T4", "--top-ports", "100"]
    },

    "standard": {
        "name": "Standard Scan",
        "nmap_args": ["-T4", "--top-ports", "1000"]
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