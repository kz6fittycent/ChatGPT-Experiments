# ChatGPT Generated Scripts

These scripts were created while I was trying different ideas with ChatGPT. They are in various states of effectiveness, usefulness, and capability. 

Use at your own risk! :) 

## Scripts in this repo:

[Apache Checker](https://github.com/kz6fittycent/ChatGPT-Experiments/blob/master/Scripts/apache_checker.py)
- This script can perform a configuration check on a given apache site configuration file and ensure that best practices are applied and offer the changes be automatically made. A backup is created should the admin decide to allow the script to make the changes. 

[Ascii Art Generator](https://github.com/kz6fittycent/ChatGPT-Experiments/blob/master/Scripts/ascii.py)
- This script is pretty fun. You can generate some ascii art within your terminal for use in other scripts or something. Not every font enumerated works and I'm not sure why, but it's good enough for a start!

[Host Enumerator](https://github.com/kz6fittycent/ChatGPT-Experiments/blob/master/Scripts/host_enumerator.py)
- This script I find fairly useful. It can do a full host enumeration on your private network with all open ports. This could be extended to include hostname and mac address. I could also see a report generated to find any known vulnerabilties that one could address. 

[Message Encryptor](https://github.com/kz6fittycent/ChatGPT-Experiments/blob/master/Scripts/message_encryptor.py)
- This script is pretty useful. It encrypts messages with FIPS 140-2 compliance and allows the sender to create a password for the file and one for the recipient. It also generates a sha256sum for the recipient to ensure message file integrity. There are shortcomings, but it's usable.

[Ubuntu Vulnerability Checker](https://github.com/kz6fittycent/ChatGPT-Experiments/blob/master/Scripts/ubuntu_vuln_checker.py)
- This one works fairly well. It uses [VulDB's API](https://vuldb.com) to check for vulnerabilties on a local system (Ubuntu-based only). I had intially asked ChatGPT to make the script capable of checking any Linux-based OS, but it wasn't able to do so (tested on RHEL and Ubuntu). 
