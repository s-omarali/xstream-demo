# XStream 1.4.17 demo app — SpotBugs/FindSecBugs target

Needs: JDK 11+ and Maven.

## 1. Build and scan
```
mvn clean compile
mvn spotbugs:spotbugs     # writes target/spotbugsXml.xml
mvn spotbugs:gui          # browse findings (screenshot these for the report)
```

## 2. Scan the XStream library itself
Open the SpotBugs GUI (or CLI) on `~/.m2/repository/com/thoughtworks/xstream/xstream/1.4.17/xstream-1.4.17.jar`
with the FindSecBugs plugin enabled, and record those findings separately.

## 3. What to expect / note in the report
| Location | Issue | CWE | Expected detector |
|---|---|---|---|
| `handleImportVulnerable` – `new File("imports", fileName)` | Path traversal | CWE-22 | FindSecBugs `PATH_TRAVERSAL_IN` |
| `handleOrderVulnerable` – `fromXML(body)` | Untrusted deserialization | CWE-502 | Likely **not** flagged out of the box → custom detector |
| `handleImportVulnerable` – `fromXML(in)` | Untrusted deserialization | CWE-502 | Same as above |
| `handleOrderSafe` | Allow-list configured | — | Should be clean (shows remediation) |

The gap in row 2/3 is the motivation for the custom SpotBugs rule (flag `XStream.fromXML`
when no `allowTypes`/`addPermission` call was made on that instance).

## 4. Optional: run it
```
mvn exec:java -Dexec.mainClass=edu.uta.cse4382.demo.OrderServer
curl -X POST --data "<order><customer>Ana</customer><item>Pen</item><quantity>2</quantity></order>" http://127.0.0.1:8080/order
```
Binds to localhost only. Do not expose it.
