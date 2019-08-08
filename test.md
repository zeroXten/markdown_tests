# Myapp Example Project Threat Model

An example project.

## Exposures

### Cross-site Scripting against WebApp:App

### content injection against WebApp:App

## Acceptances

## Transfers

## Mitigations

## Reviews

## Connections

## Components

| Name/Id | Description | Paths | Custom | Source |
| ------- | ----------- | ----- | ------ | ------ |
| **WebApp:FileSystem**<br><br>(#filesystem) |  |  WebApp<br/>  |  | MyApp Example Project<br><br>`// @accepts #file_writes to WebApp:FileSystem with filename restrictions that limit the possible filenames written to by an attacker<br>func (p *Page) save() error {<br>    filename := p.Title + ".txt"<br>    return ioutil.WriteFile(filename, p.Body, 0600)<br>}<br><br>`<br><br>...les/go_source/simple_web.go:1 |
| **WebApp:App**<br><br>(#app) |  |  WebApp<br/>  |  | MyApp Example Project<br><br>`// @exposes WebApp:App to #xss with insufficient input validation<br>func editHandler(w http.ResponseWriter, r *http.Request, title string) {<br>    p, err := loadPage(title)<br>    if err != nil {<br>        p = &Page{Title: title}<br>    }<br>`<br><br>...les/go_source/simple_web.go:1 |
| **WebApp:Web**<br><br>(#web) |  |  WebApp<br/>  |  | MyApp Example Project<br><br>`// @mitigates WebApp:Web against resource access abuse with basic input validation<br>func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {<br>    return func(w http.ResponseWriter, r *http.Request) {<br>        m := validPath.FindStringSubmatch(r.URL.Path)<br>        if m == nil {<br>            http.NotFound(w, r)<br>`<br><br>...les/go_source/simple_web.go:1 |
| **User:Browser**<br><br>(#browser) |  |  User<br/>  |  | MyApp Example Project<br><br>`// @transfers @cwe_319_cleartext_transmission from WebApp:Web to User:Browser with non-sensitive information<br>func main() {<br>    flag.Parse()<br>    http.HandleFunc("/view/", makeHandler(viewHandler))<br>    http.HandleFunc("/edit/", makeHandler(editHandler))<br>    http.HandleFunc("/save/", makeHandler(saveHandler))<br>`<br><br>...les/go_source/simple_web.go:1 |

## Threats

| Name/Id | Description | Paths | Custom | Source |
| ------- | ----------- | ----- | ------ | ------ |
| **arbitrary file writes**<br><br>(#file_writes) | An attacker can make arbitrary changes to files on the file system, for example overwriting /etc/hosts. |  | **impact**: high<br> | MyApp Example Project<br><br>`<br>package main<br><br>import (<br>    "flag"<br>`<br><br>...les/go_source/simple_web.go:5 |
| **Cross-site Scripting**<br><br>(#xss) | Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables <br>attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be <br>used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites <br>accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007. (Wikipedia) |  |  | MyApp Example Project<br><br>`<br>package main<br><br>import (<br>    "flag"<br>`<br><br>...les/go_source/simple_web.go:5 |
| **arbitrary file reads**<br><br>(#arbitrary_file_reads) |  |  |  | MyApp Example Project<br><br>`// @accepts arbitrary file reads to WebApp:FileSystem with filename restrictions<br>func loadPage(title string) (*Page, error) {<br>    filename := title + ".txt"<br>    body, err := ioutil.ReadFile(filename)<br>    if err != nil {<br>        return nil, err<br>`<br><br>...les/go_source/simple_web.go:1 |
| **content injection**<br><br>(#content_injection) |  |  |  | MyApp Example Project<br><br>`// @exposes WebApp:App to content injection with insufficient input validation<br>func saveHandler(w http.ResponseWriter, r *http.Request, title string) {<br>    body := r.FormValue("body")<br>    p := &Page{Title: title, Body: []byte(body)}<br>    err := p.save()<br>    if err != nil {<br>`<br><br>...les/go_source/simple_web.go:1 |
| **resource access abuse**<br><br>(#resource_access_abuse) |  |  |  | MyApp Example Project<br><br>`// @mitigates WebApp:Web against resource access abuse with basic input validation<br>func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {<br>    return func(w http.ResponseWriter, r *http.Request) {<br>        m := validPath.FindStringSubmatch(r.URL.Path)<br>        if m == nil {<br>            http.NotFound(w, r)<br>`<br><br>...les/go_source/simple_web.go:1 |
| **privilege escalation**<br><br>(#privilege_escalation) |  |  |  | MyApp Example Project<br><br>`// @mitigates WebApp:Web against privilege escalation with non-privileged port<br>func main() {<br>    flag.Parse()<br>    http.HandleFunc("/view/", makeHandler(viewHandler))<br>    http.HandleFunc("/edit/", makeHandler(editHandler))<br>    http.HandleFunc("/save/", makeHandler(saveHandler))<br>`<br><br>...les/go_source/simple_web.go:1 |
| **@cwe_319_cleartext_transmission**<br><br>(#cwe_319_cleartext_transmission) |  |  |  | MyApp Example Project<br><br>`// @transfers @cwe_319_cleartext_transmission from WebApp:Web to User:Browser with non-sensitive information<br>func main() {<br>    flag.Parse()<br>    http.HandleFunc("/view/", makeHandler(viewHandler))<br>    http.HandleFunc("/edit/", makeHandler(editHandler))<br>    http.HandleFunc("/save/", makeHandler(saveHandler))<br>`<br><br>...les/go_source/simple_web.go:1 |
| **An example library threat**<br><br>(#an_example_library_threat) | Must fill this in a bit I think |  | **impact**: high<br> | CWE Threat Library<br><br>``<br><br>./cwe.threatspec.txt:5 |
| **Another library threat**<br><br>(#another_library_threat) | Just for good measure |  | **impact**: low<br> | CWE Threat Library<br><br>``<br><br>./cwe.threatspec.txt:5 |

## Controls

| Name/Id | Description | Paths | Custom | Source |
| ------- | ----------- | ----- | ------ | ------ |
| **basic input validation**<br><br>(#basic_input_validation) |  |  |  | MyApp Example Project<br><br>`// @mitigates WebApp:Web against resource access abuse with basic input validation<br>func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {<br>    return func(w http.ResponseWriter, r *http.Request) {<br>        m := validPath.FindStringSubmatch(r.URL.Path)<br>        if m == nil {<br>            http.NotFound(w, r)<br>`<br><br>...les/go_source/simple_web.go:1 |
| **non-privileged port**<br><br>(#nonprivileged_port) |  |  |  | MyApp Example Project<br><br>`// @mitigates WebApp:Web against privilege escalation with non-privileged port<br>func main() {<br>    flag.Parse()<br>    http.HandleFunc("/view/", makeHandler(viewHandler))<br>    http.HandleFunc("/edit/", makeHandler(editHandler))<br>    http.HandleFunc("/save/", makeHandler(saveHandler))<br>`<br><br>...les/go_source/simple_web.go:1 |


