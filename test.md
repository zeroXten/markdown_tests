# Threatspec project Threat Model

A threatspec project.


# Diagram
![Threat Model Diagram](ThreatModel.md.png)



# Exposures

## Cross-site scripting against WebApp:App
Insufficient input validation

```
func editHandler(w http.ResponseWriter, r *http.Request, title string) {
    p, err := loadPage(title)
    if err != nil {
        p = &Page{Title: title}
    }

```
/home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:72

## Content injection against WebApp:App
Insufficient input validation

```
func saveHandler(w http.ResponseWriter, r *http.Request, title string) {
    body := r.FormValue("body")
    p := &Page{Title: title, Body: []byte(body)}
    err := p.save()
    if err != nil {

```
/home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:81


# Acceptances

## Arbitrary file writes to WebApp:FileSystem
Filename restrictions that limit the possible filenames written to by an attacker

```
func (p *Page) save() error {
    filename := p.Title + ".txt"
    return ioutil.WriteFile(filename, p.Body, 0600)
}


```
/home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:43

## Arbitrary file reads to WebApp:FileSystem
Filename restrictions

```
func loadPage(title string) (*Page, error) {
    filename := title + ".txt"
    body, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err

```
/home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:53


# Transfers


# Mitigations

## Resource access abuse against WebApp:Web with Basic input validation


```
func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        m := validPath.FindStringSubmatch(r.URL.Path)
        if m == nil {
            http.NotFound(w, r)

```
/home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:104

## Privilege escalation against WebApp:Web with Non-privileged port

### Tests

#### Non-privileged port for WebApp:Web

```

```
/home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:142



```
func main() {
    flag.Parse()
    http.HandleFunc("/view/", makeHandler(viewHandler))
    http.HandleFunc("/edit/", makeHandler(editHandler))
    http.HandleFunc("/save/", makeHandler(saveHandler))

```
/home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:116


# Reviews

## WebApp:Web
Is this a security feature?

```
        if err != nil {
            log.Fatal(err)
        }
        s := &http.Server{}
        s.Serve(l)

```
/home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:129


# Connections

## User:Browser To WebApp:Web
HTTP:8080

```

```
/home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:138


# Components

## resource access abuse

## privilege escalation

## Cross-site Scripting
| Impact | high |


### Description
Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables 
attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be 
used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites 
accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007. (Wikipedia)


## content injection

## @cwe_319_cleartext_transmission

## arbitrary file writes
| Impact | high |


### Description
An attacker can make arbitrary changes to files on the file system, for example overwriting /etc/hosts.


## arbitrary file reads


# Threats

## Resource access abuse


## Privilege escalation


## Cross-site scripting
| Impact | high |



### Description
Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables 
attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be 
used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites 
accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007. (Wikipedia)


## Content injection


## @cwe_319_cleartext_transmission


## Arbitrary file writes
| Impact | high |



### Description
An attacker can make arbitrary changes to files on the file system, for example overwriting /etc/hosts.


## Arbitrary file reads



# Controls

## Non-privileged port

## Basic input validation
