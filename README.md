# PHP-Unrestricted-Upload-RCE
A Critical (CVSS 10.0) RCE vulnerability in a PHP e-commerce platform. The app trusts client-side MIME types and preserves extensions during upload. Attackers can bypass checks to upload web shells, gaining full system access (www-data). Includes PoC for bypassing validation via curl
