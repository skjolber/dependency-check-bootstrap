INSERT INTO reference (cveid, name, url, source)
SELECT cveid, name, url, source
FROM BINARY_REFERENCE('%1$s');
