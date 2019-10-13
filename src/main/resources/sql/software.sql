INSERT INTO software (cveid, cpeEntryId, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding, vulnerable)
SELECT cveid, cpeEntryId, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding, vulnerable
FROM CSVREAD('%1$s');
