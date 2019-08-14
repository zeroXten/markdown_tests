
# Myapp Example Project Threat Model

An example project.

## Exposures

The following threats against components have not been mitigated.

### Cross-Site Scripting against WebApp:App

Insufficient input validation

```
// @exposes WebApp:App to #xss with insufficient input validation
func editHandler(w http.ResponseWriter, r *http.Request, title string) {
    p, err := loadPage(title)
    if err != nil {
        p = &Page{Title: title}
    }

```
...pec/threatspec_examples/go_source/simple_web.go:1 in MyApp Example Project

### Content Injection against WebApp:App

Insufficient input validation

```
// @exposes WebApp:App to content injection with insufficient input validation
func saveHandler(w http.ResponseWriter, r *http.Request, title string) {
    body := r.FormValue("body")
    p := &Page{Title: title, Body: []byte(body)}
    err := p.save()
    if err != nil {

```
...pec/threatspec_examples/go_source/simple_web.go:1 in MyApp Example Project

## Acceptances

The following threats against components have been accepted and will not be mitigated.

### Arbitrary File Writes against WebApp:FileSystem

Filename restrictions that limit the possible filenames written to by an attacker

```
// @accepts #file_writes to WebApp:FileSystem with filename restrictions that limit the possible filenames written to by an attacker
func (p *Page) save() error {
    filename := p.Title + ".txt"
    return ioutil.WriteFile(filename, p.Body, 0600)
}


```
...pec/threatspec_examples/go_source/simple_web.go:1 in MyApp Example Project

### Arbitrary File Reads against WebApp:FileSystem

Filename restrictions

```
// @accepts arbitrary file reads to WebApp:FileSystem with filename restrictions
func loadPage(title string) (*Page, error) {
    filename := title + ".txt"
    body, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err

```
...pec/threatspec_examples/go_source/simple_web.go:1 in MyApp Example Project

## Transfers
These threats have been transfered from one component to another, and are expected to be handled in some way by the destination component.

### @cwe_319_cleartext_transmission from WebApp:Web to User:Browser

Non-sensitive information

```
// @transfers @cwe_319_cleartext_transmission from WebApp:Web to User:Browser with non-sensitive information
func main() {
    flag.Parse()
    http.HandleFunc("/view/", makeHandler(viewHandler))
    http.HandleFunc("/edit/", makeHandler(editHandler))
    http.HandleFunc("/save/", makeHandler(saveHandler))

```
...pec/threatspec_examples/go_source/simple_web.go:1 in MyApp Example Project


## Mitigations
These threats have been mitigated by a control, and possibly have tests to ensure those mitigates are behaving as expected.

### Resource Access Abuse against WebApp:Web mitigated by Basic Input Validation



```
// @mitigates WebApp:Web against resource access abuse with basic input validation
func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        m := validPath.FindStringSubmatch(r.URL.Path)
        if m == nil {
            http.NotFound(w, r)

```
...pec/threatspec_examples/go_source/simple_web.go:1 in MyApp Example Project

### Privilege Escalation against WebApp:Web mitigated by Non-Privileged Port



```
// @mitigates WebApp:Web against privilege escalation with non-privileged port
func main() {
    flag.Parse()
    http.HandleFunc("/view/", makeHandler(viewHandler))
    http.HandleFunc("/edit/", makeHandler(editHandler))
    http.HandleFunc("/save/", makeHandler(saveHandler))

```
...pec/threatspec_examples/go_source/simple_web.go:1 in MyApp Example Project

## Reviews
The following reviews have been created to track concerns, assumptions, questions that may require further investigation or research.

### WebApp:Web
### Review
Is this a security feature?

```
        err = ioutil.WriteFile("final-port.txt", []byte(l.Addr().String()), 0644) // @review WebApp:Web Is this a security feature?
        if err != nil {
            log.Fatal(err)
        }
        s := &http.Server{}
        s.Serve(l)

```
...les/go_source/simple_web.go:1 in MyApp Example Project

## Connections
This is a list of connectivity between components. This could be network connectivity, logical, data flow or anything else.

| Source component | Destination component | Details | Description | Custom | Source |
| ---------------- | --------------------- | ------- | ----------- | ------ | ------ |
| User:Browser | WebApp:Web | HTTP:8080 |  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1

## Components

| Name/Id | Description | Paths | Custom | Source |
| ------- | ----------- | ----- | ------ | ------ |
| **WebApp:FileSystem**<br><br>(#filesystem) |  |  WebApp<br/>  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |
| **WebApp:App**<br><br>(#app) |  |  WebApp<br/>  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |
| **WebApp:Web**<br><br>(#web) |  |  WebApp<br/>  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |
| **User:Browser**<br><br>(#browser) |  |  User<br/>  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |

## Threats

| Name/Id | Description | Paths | Custom | Source |
| ------- | ----------- | ----- | ------ | ------ |
| **arbitrary file writes**<br><br>(#file_writes) | An attacker can make arbitrary changes to files on the file system, for example overwriting /etc/hosts. |  | **impact**: high<br> | MyApp Example Project<br><br>...les/go_source/simple_web.go:5 |
| **Cross-site Scripting**<br><br>(#xss) | Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables <br>attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be <br>used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites <br>accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007. (Wikipedia) |  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:5 |
| **arbitrary file reads**<br><br>(#arbitrary_file_reads) |  |  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |
| **content injection**<br><br>(#content_injection) |  |  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |
| **resource access abuse**<br><br>(#resource_access_abuse) |  |  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |
| **privilege escalation**<br><br>(#privilege_escalation) |  |  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |
| **@cwe_319_cleartext_transmission**<br><br>(#cwe_319_cleartext_transmission) |  |  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |
| **An example library threat**<br><br>(#an_example_library_threat) | Must fill this in a bit I think |  | **impact**: high<br> | CWE Threat Library<br><br>./cwe.threatspec.txt:5 |
| **Another library threat**<br><br>(#another_library_threat) | Just for good measure |  | **impact**: low<br> | CWE Threat Library<br><br>./cwe.threatspec.txt:5 |

## Controls

| Name/Id | Description | Paths | Custom | Source |
| ------- | ----------- | ----- | ------ | ------ |
| **basic input validation**<br><br>(#basic_input_validation) |  |  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |
| **non-privileged port**<br><br>(#nonprivileged_port) |  |  |  | MyApp Example Project<br><br>...les/go_source/simple_web.go:1 |


