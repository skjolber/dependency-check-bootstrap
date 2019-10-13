INSERT INTO reference (cveid, name, url, source)
SELECT cveid, name, url, source
FROM CSVREAD('%1$s');
