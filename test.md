# Myapp Example Project Threat Model

An example project.
# Threats
| Name | Description | Project ID |
| ---- | ----------- | ---------- |
| arbitrary file writes | An attacker can make arbitrary changes to files on the file system, for example overwriting /etc/hosts. | #myapp |
| Cross-site Scripting | Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables 
attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be 
used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites 
accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007. (Wikipedia) | #myapp |
| arbitrary file reads |  | #myapp |
| content injection |  | #myapp |
| resource access abuse |  | #myapp |
| privilege escalation |  | #myapp |
| @cwe_319_cleartext_transmission |  | #myapp |
| An example library threat | Must fill this in a bit I think | #cwe |
| Another library threat | Just for good measure | #cwe |
