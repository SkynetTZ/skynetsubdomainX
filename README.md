# skynetsubdomainX
A modern passive subdomain enumerator built for cybersecurity professionals.

<img width="1254" height="1254" alt="hu" src="https://github.com/user-attachments/assets/8699fb4a-7fa3-4f90-b5b8-4c7587046054" />


# Features

- Multi-source passive collection:
  - `crt.sh`
  - `ThreatCrowd`
  - `HackerTarget`
  - `Wayback Machine`
- Built-in de-duplication and result cleaning
- Optional DNS resolution for discovered hosts
- Rich terminal tables and progress indicators
- Save output directly to file

# Install

```bash
git clone https://github.com/SkynetTZ/skynetsubdomain
cd skynetsubdomain
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

# Usage

```bash
skynetsubdomain example.com
```

Options:

- `-t, --timeout`: source request timeout (default `10`)
- `-w, --workers`: concurrent workers (default `8`)
- `--no-resolve`: skip DNS resolution
- `-o, --output`: write subdomains to a file

Example:

```bash
skynetsubdomain tesla.com -w 16 -o results/tesla.txt
```
