# OWASP dependency check bootstrap experiment

Simple demonstration of bootstrapping the OWASP dependency check database file 
via CSV files for the special (but common) case of using an H2 database 
(with a local database file). 

In other words, starting with a fresh database and inserting NIST JSON feeds for for the years 2002 to 2019.

In a nutshell:

 * process while downloading in the start, then download + process in parallel tasks
 * runs csv inserts in parallel tasks
 * add constraints after inserting all the data (in sequence, seems there is a lock on updating table and/or database constraints)

# Results (disclaimer: ballpark numbers)
On a 4+4 core laptop with a fiber connection. 

Includes download, but not latest updates nor database maintenance.

## JDBC insert approach (original)
Runs in approximately 128 seconds:

```
Got 1709408 rows for software
Got 201434 rows for cpeEntry (this number seems to vary by a few from run to run)
Got 534671 rows for reference
Got 102259 rows for vulnerability
Got 103270 rows for cweEntry
```

Modified `NvdCveUpdaterIT` and uncomment `if (runLast != null)` and `cveDb.cleanupDatabase();` in `NvdCveUpdater`.

## JDBC CSV insert approach
Runs in approximately 52 seconds:

```
Got 1709408 rows for software
Got 201431 rows for cpeEntry
Got 534671 rows for reference
Got 102259 rows for vulnerability
Got 103270 rows for cweEntry
```

Run it using the command 

```
mvn clean package && java -jar target/h2-bootstrap-0.0.1-SNAPSHOT-jar-with-dependencies.jar
```

## JDBC insert with improved multi-threading approach
Was unable to improve much on this by using more connections / multi-threading. 
CPU use seems to not exceed about 150% very often.

## JDBC insert with custom java bean datasource
Inefficient due to layers of wrapping.
