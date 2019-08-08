# Myapp Example Project Threat Model

An example project.
# Threats
| Name | Description | Source |
| ---- | ----------- | ------- |
| Arbitrary File Writes | An attacker can make arbitrary changes to files on the file system, for example overwriting /etc/hosts. | MyApp Example Project<br>...les/go_source/simple_web.go:5 |
| Cross-Site Scripting | Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables <br>attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be <br>used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites <br>accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007. (Wikipedia) | MyApp Example Project<br>...les/go_source/simple_web.go:5 |
| Arbitrary File Reads |  | MyApp Example Project<br>...les/go_source/simple_web.go:1 |
| Content Injection |  | MyApp Example Project<br>...les/go_source/simple_web.go:1 |
| Resource Access Abuse |  | MyApp Example Project<br>...les/go_source/simple_web.go:1 |
| Privilege Escalation |  | MyApp Example Project<br>...les/go_source/simple_web.go:1 |
| @cwe_319_cleartext_transmission |  | MyApp Example Project<br>...les/go_source/simple_web.go:1 |
| An Example Library Threat | Must fill this in a bit I think | CWE Threat Library<br>./cwe.threatspec.txt:5 |
| Another Library Threat | Just for good measure | CWE Threat Library<br>./cwe.threatspec.txt:5 |
