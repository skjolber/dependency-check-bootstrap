INSERT INTO cweEntry (cveid, cwe)
SELECT cveid, cwe
FROM CSVREAD('%1$s');
