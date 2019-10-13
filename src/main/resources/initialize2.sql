DROP TABLE IF EXISTS vulnerability;

CREATE TABLE vulnerability (id int auto_increment PRIMARY KEY, cve VARCHAR(20) UNIQUE,
	description VARCHAR(8000), cvssV2Score DECIMAL(3,1), cvssV2AccessVector VARCHAR(20),
	cvssV2AccessComplexity VARCHAR(20), cvssV2Authentication VARCHAR(20), cvssV2ConfidentialityImpact VARCHAR(20),
	cvssV2IntegrityImpact VARCHAR(20), cvssV2AvailabilityImpact VARCHAR(20), cvssV2Severity VARCHAR(20),
        cvssV3AttackVector VARCHAR(20), cvssV3AttackComplexity VARCHAR(20), cvssV3PrivilegesRequired VARCHAR(20),
        cvssV3UserInteraction VARCHAR(20), cvssV3Scope VARCHAR(20), cvssV3ConfidentialityImpact VARCHAR(20),
        cvssV3IntegrityImpact VARCHAR(20), cvssV3AvailabilityImpact VARCHAR(20), cvssV3BaseScore DECIMAL(3,1), 
        cvssV3BaseSeverity VARCHAR(20));

CREATE INDEX idxVulnerability ON vulnerability(cve);

INSERT INTO vulnerability (id, cve, description, cvssV2Score, cvssV2AccessVector, cvssV2AccessComplexity, cvssV2Authentication, cvssV2ConfidentialityImpact, cvssV2IntegrityImpact, cvssV2AvailabilityImpact, cvssV2Severity, cvssV3AttackVector, cvssV3AttackComplexity, cvssV3PrivilegesRequired, cvssV3UserInteraction, cvssV3Scope, cvssV3ConfidentialityImpact, cvssV3IntegrityImpact, cvssV3AvailabilityImpact, cvssV3BaseScore, cvssV3BaseSeverity) 
SELECT id, cve, description, convert(cvssV2Score, DECIMAL(3,1)), cvssV2AccessVector, cvssV2AccessComplexity, cvssV2Authentication, cvssV2ConfidentialityImpact, cvssV2IntegrityImpact, cvssV2AvailabilityImpact, cvssV2Severity, cvssV3AttackVector, cvssV3AttackComplexity, cvssV3PrivilegesRequired, cvssV3UserInteraction, cvssV3Scope, cvssV3ConfidentialityImpact, cvssV3IntegrityImpact, cvssV3AvailabilityImpact, convert(cvssV3BaseScore, DECIMAL(3,1)), cvssV3BaseSeverity
FROM CSVREAD('/tmp/cve2008_8596082657656758476.json.gz/owasp.vulnerability.v2v3.csv');
        