# OWASP dependency checks (H2) bootstrap

Simple demonstration of bootstrapping the OWASP dependency check database file 
via CSV files for the special (but common) case of using an H2 database 
(with a local datbase file). 

In other words, starting with a fresh database and inserting NIST JSON feeds for for the years 2002 to 2019.

In a nutshell:

 * process while downloading in the start, then download + process in separate tasks
 * runs csv inserts in separate tasks
 * add constraints after inserting all the data

# results

## JDBC approach (original)
Runs in approximately 148628ms:

```
Got 1709408 rows for software
Got 201434 rows for cpeEntry
Got 534671 rows for reference
Got 102259 rows for vulnerability
Got 103270 rows for cweEntry
```

## CSV approach
Runs in approximately 55455ms:

```
Got 1709408 rows for software
Got 201431 rows for cpeEntry
Got 534671 rows for reference
Got 102259 rows for vulnerability
Got 103270 rows for cweEntry
```
