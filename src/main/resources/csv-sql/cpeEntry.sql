INSERT INTO cpeEntry (id, part, vendor, product, version, update_version, edition, lang, sw_edition, target_sw, target_hw, other, ecosystem) 
SELECT id, part, vendor, product, version, update_version, edition, lang, sw_edition, target_sw, target_hw, other, ecosystem
FROM CSVREAD('%1$s');
