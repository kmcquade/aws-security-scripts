# aws-security-scripts

* `calculate_security_group_rule_changes.py`: Calculates non-company IP Addresess
* `find_public_instances_with_roles.py`: Find EC2 instances with Public IPs that have IAM roles attached.
* `analyze_public_instances_results.py`: Analyzes the results files of your scan with the `find_public_instances.py` report. It generates report summaries in `results.csv` and `results.json` files.

## Requirements

* Python 3
* AWS IAM Role: SecurityAuditRole (for the public instances scripts)

## Instructions

### Calculate non-company CIDR ranges

```
git clone https://github.com/kmcquade/aws-security-scripts.git
cd aws-security-scripts
pipenv shell
pipenv install
./calculate_public_cidrs.py
```

It will print this:

```text
Printed non-company CIDRs to file: /Users/kmcquade/Code/GitHub/kmcquade/aws-security-scripts/policy/exceptions/

Illegal CIDRs:
[
  "0.0.0.0/5",
  "8.0.0.0/7",
  "11.0.0.0/8",
  "12.0.0.0/6",
  "16.0.0.0/4",
  "32.0.0.0/3",
  "64.0.0.0/2",
  "128.0.0.0/3",
  "160.0.0.0/5",
  "168.0.0.0/6",
  "172.0.0.0/12",
  "172.32.0.0/11",
  "172.64.0.0/10",
  "172.128.0.0/9",
  "173.0.0.0/8",
  "174.0.0.0/7",
  "176.0.0.0/4",
  "192.0.0.0/9",
  "192.128.0.0/11",
  "192.160.0.0/13",
  "192.169.0.0/16",
  "192.170.0.0/15",
  "192.172.0.0/14",
  "192.176.0.0/12",
  "192.192.0.0/10",
  "193.0.0.0/8",
  "194.0.0.0/7",
  "196.0.0.0/6",
  "200.0.0.0/5",
  "208.0.0.0/4",
  "224.0.0.0/3"
]
```

### Find privileged public instances

```bash
git clone https://github.com/kmcquade/aws-security-scripts.git
cd aws-security-scripts
pipenv shell
pipenv install
./find_public_instances_with_roles.py
```

It will print stuff like this:

```text
Region: us-east-2
FOUND! Instance: i-01234567e89012ea1, Public IP: 104.83.225.8, Role: S3_Full_Jeffrey
FOUND! Instance: i-01234567e89012ea2, Public IP: 184.30.190.174, Role: SMS_Full_Epstein
Region: us-west-1
FOUND! Instance: i-01234567e89012ea3, Public IP: 23.194.161.11, Role: EC2_Full_Didnt
FOUND! Instance: i-01234567e89012ea4, Public IP: 104.83.225.8, Role: DMS_Full_Hang
FOUND! Instance: i-01234567e89012ea4, Public IP: 23.32.161.205, Role: IAM_Full_Himself
Account ID 012345678901 report saved to /Users/kmcquade/Code/aws-security-scripts/reports/accounts//default.json
```

It will generate a report to the path `reports/accounts/default.json`


## Options

* `calculate_public_cidrs.py`

```text
Usage: calculate_public_cidrs.py [OPTIONS]

Options:
  --input-file PATH   The path to the company_cidrs.yml file, which should
                      contain a list of company-only CIDR ranges. The example
                      just has RFC1918 CIDRs.
  --output-file PATH  The directory to store the non_company_cidrs.yml file
  --help              Show this message and exit.
```

* `find_public_instances_with_roles.py`

```text
Options:
  --credentials-file PATH  AWS shared credentials file. Defaults to
                           ~/.aws/credentials
  --recursive              Use this flag to download from **all** accounts
                           listed in the credentials file. Defaults to false.
  --profile TEXT           To authenticate to AWS and scan just one profile.
  --all-regions            Audit all regions, not just US regions. This will
                           be VERY slow if you are scanning a lot of accounts.
  --output PATH            The directory where you will store the report
                           output. Defaults to ./reports/accounts/
  --help                   Show this message and exit.
```

* `analyze_public_instances_results.py`

```text
Usage: analyze_public_instances_results.py [OPTIONS]

Options:
  --input-file PATH  Path to the JSON file you want to analyze, or a directory
                     of those files. Defaults to the directory
                     "./reports/accounts/"
  --output PATH      Directory to store the reports. Defaults to "/reports/"
  --help             Show this message and exit.
```
