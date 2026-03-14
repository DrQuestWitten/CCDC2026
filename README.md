# Wayne State CCDC Team Repository

## Overview

This repository contains tools, documentation, and resources used by the **Wayne State University CCDC Team** to prepare for and compete in the **Collegiate Cyber Defense Competition (CCDC)**.

The goal of this repository is to centralize:

* Defensive security scripts
* System hardening guides
* Incident response playbooks
* Team documentation
* Competition preparation resources

This allows team members to quickly deploy defenses, investigate incidents, and maintain system availability during competitions.

## Script Documentation

### Linux
For Linux hardening scripts, install the correct script to your system and run:

- sudo chmod +x <script>.sh
- ./<script>.sh


Linux Wazuh Scripts:

To deploy the Wazuh agent on each linux machine, adjust the WAZUH_MANAGER IP address in both the ossec.conf, and agent.sh files. It is also required to ensure that the Agent Name section in both is identical and human-readable. Select the correct Wazuh scripts for your respective machine.
- Wazuh Agent requires ports 1514 and 1515 to be open on your machine

### Windows


---

## Best Practices During Competition

* Document all actions taken
* Avoid deleting files unless necessary
* Preserve logs when investigating incidents
* Maintain communication with teammates
* Verify service functionality after making changes
* Test changes before deploying when possible

---

## Contributing

Team members are encouraged to contribute by:

* Adding useful security scripts
* Improving documentation
* Updating hardening guides
* Fixing issues or bugs

## Disclaimer

These tools and resources are intended **only for defensive cybersecurity use in authorized environments**, including:

* CCDC competitions
* Cybersecurity labs
* Educational environments

Do **not use these tools on systems without permission**.

---

## Team Members - 2026
Hussein Abdullah - Team Captain / Linux Lead

Christopher Seman - Windows Lead

Mehdi Mirnajafi - Network Lead

Michael Abood - Tech Lead / Networking

Keegan Miller - Oracle Splunk / Fedora Webmail

Abdul Shakib - Server 19 Web

Adam Mayberry - Orange Team Correspondence

Sebastian Newberry - Server 22 FTP

Drabir Sen - Windows Substitute

## Advisors - 2026
Professor Doug Witten

Professor Rhongho Jang

## License

This repository is intended for **educational and competition purposes only**.
