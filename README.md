# Blast Furnace

### A Golden gMSA refinement project

Previous work has focused on leveraging a windows target or attacker station for conducting the golden gMSA attack. This project focuses on enabling an red teamer to perform the attack entirely remotely without the need for window's dependencies. This means the full attack chain can be performed via Linux and through proxychains if necessary. Furthermore, the gMSA keys can be generated entirely offline using only python libraries and the required KDS attributes.

### Usage:

```bash
usage: BlastFurnace [-h]  ...

█▄▄ █░░ ▄▀█ █▀ ▀█▀ █▀▀ █░█ █▀█ █▄░█ ▄▀█ █▀▀ █▀▀
█▄█ █▄▄ █▀█ ▄█ ░█░ █▀░ █▄█ █▀▄ █░▀█ █▀█ █▄▄ ██▄
A refinement on the Golden gMSA attack tool

options:
  -h, --help  show this help message and exit

commands:
  
    auto      run command in full auto mode
    offline   offline mode, all material required
```
