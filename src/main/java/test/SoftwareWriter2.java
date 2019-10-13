package test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.apache.commons.io.IOUtils;
import org.owasp.dependencycheck.analyzer.exception.LambdaExceptionWrapper;
import org.owasp.dependencycheck.data.nvd.json.CpeMatchStreamCollector;
import org.owasp.dependencycheck.data.nvd.json.DefCpeMatch;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.NodeFlatteningCollector;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.opencsv.CSVWriter;

import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

public class SoftwareWriter2 {

    private static final Logger LOGGER = LoggerFactory.getLogger(SoftwareWriter2.class);

	private static Map<String, Integer> softwares = new HashMap<>();
	private static AtomicInteger counter = new AtomicInteger(1);
   
	private CSVWriter cpeEntryWriter;
	private Path cpeEntryPath;

	private CSVWriter softwareWriter;
	
	private String cpeStartsWithFilter;
	
    private final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();

    private int softwareCount = 0;
    private String softwareTemplate = "owasp.software.%d.csv";
    private Path directory;
    
    private int softwareRows = 0;
    private int softwareLimit = 10000000;
    
	public SoftwareWriter2(Path directory, Settings settings) {
		this.directory = directory;
		
		cpeEntryPath = directory.resolve("owasp.cpeEntry.csv");
		
        this.cpeStartsWithFilter = settings.getString(Settings.KEYS.CVE_CPE_STARTS_WITH_FILTER, "cpe:2.3:a:");
	}	
	
	private Path nextSoftwareFileName() {
		String fileName = String.format(softwareTemplate, softwareCount);
		softwareCount++;
		
		return directory.resolve(fileName);
	}

    public void write(int vulnerabilityId, DefCveItem cve, String baseEcosystem) throws Exception {
    	final List<VulnerableSoftware> software = parseCpes(cve);

        String[] insert = new String[7];

        for (VulnerableSoftware parsedCpe : software) {
            int cpeProductId = spawnVulnerableSoftware(parsedCpe, baseEcosystem);

            insert[0] = Integer.toString(vulnerabilityId);
            insert[1] = Integer.toString(cpeProductId);
            insert[2] = parsedCpe.getVersionEndExcluding();
            insert[3] = parsedCpe.getVersionEndIncluding();
            insert[4] = parsedCpe.getVersionStartExcluding();
            insert[5] = parsedCpe.getVersionStartIncluding();
            insert[6] = Boolean.toString(parsedCpe.isVulnerable());
            
            softwareWriter.writeNext(insert);
            
            softwareRows++;
            if( (softwareRows % softwareLimit) == 0) {
            	softwareWriter.close(); 
        		softwareWriter = new CSVWriter(Files.newBufferedWriter(nextSoftwareFileName(), StandardCharsets.UTF_8));
        		softwareWriter.writeNext(new String[]{"cveid", "cpeEntryId", "versionEndExcluding", "versionEndIncluding", "versionStartExcluding", "versionStartIncluding", "vulnerable"});
            }
        }
        
    }

	public void open() throws IOException {
		cpeEntryWriter = new CSVWriter(Files.newBufferedWriter(cpeEntryPath, StandardCharsets.UTF_8));
		cpeEntryWriter.writeNext(new String[]{"id", "part", "vendor", "product", "version", "update_version", "edition", "lang", "sw_edition", "target_sw", "target_hw", "other", "ecosystem"});
		
		softwareWriter = new CSVWriter(Files.newBufferedWriter(nextSoftwareFileName(), StandardCharsets.UTF_8));
		softwareWriter.writeNext(new String[]{"cveid", "cpeEntryId", "versionEndExcluding", "versionEndIncluding", "versionStartExcluding", "versionStartIncluding", "vulnerable"});
	}
	
	public void close() throws IOException {
		if(cpeEntryWriter != null) {
			cpeEntryWriter.close(); 
		}
		if(softwareWriter != null) {
			softwareWriter.close();
		}
	}

	public String getCpeEntrySql()  {
		try {
			return String.format(IOUtils.toString(getClass().getResourceAsStream("/sql/cpeEntry.sql"), StandardCharsets.UTF_8), cpeEntryPath.toAbsolutePath().toString());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public List<String> getVulnerableSoftwareSql()  {
		List<String> sqls = new ArrayList<>();
		System.out.println("Return " + softwareCount + " for " + directory + " software");
		try {
			String template = IOUtils.toString(getClass().getResourceAsStream("/sql/software.sql"), StandardCharsets.UTF_8);
			
			for(int i = 0; i < softwareCount; i++) {
				String fileName = String.format(softwareTemplate, softwareCount);
				Path path = directory.resolve(fileName);
				sqls.add(String.format(template, path.toAbsolutePath().toString()));
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return sqls;
	}


    /**
     * Parses the configuration entries from the CVE entry into a list of
     * VulnerableSoftware objects.
     *
     * @param cve the CVE to parse the vulnerable software entries from
     * @return the list of vulnerable software
     * @throws CpeValidationException if an invalid CPE is present
     */
    private List<VulnerableSoftware> parseCpes(DefCveItem cve) throws CpeValidationException {
        final List<VulnerableSoftware> software = new ArrayList<>();
        final List<DefCpeMatch> cpeEntries = cve.getConfigurations().getNodes().stream()
                .collect(new NodeFlatteningCollector())
                .collect(new CpeMatchStreamCollector())
                .filter(predicate -> predicate.getCpe23Uri().startsWith(cpeStartsWithFilter))
                //this single CPE entry causes nearly 100% FP - so filtering it at the source.
                .filter(entry -> !("CVE-2009-0754".equals(cve.getCve().getCVEDataMeta().getId())
                && "cpe:2.3:a:apache:apache:*:*:*:*:*:*:*:*".equals(entry.getCpe23Uri())))
                .collect(Collectors.toList());

        try {
            cpeEntries.forEach(entry -> {
                builder.cpe(parseCpe(entry, cve.getCve().getCVEDataMeta().getId()))
                        .versionEndExcluding(entry.getVersionEndExcluding())
                        .versionStartExcluding(entry.getVersionStartExcluding())
                        .versionEndIncluding(entry.getVersionEndIncluding())
                        .versionStartIncluding(entry.getVersionStartIncluding())
                        .vulnerable(entry.getVulnerable());
                try {
                    software.add(builder.build());
                } catch (CpeValidationException ex) {
                    throw new LambdaExceptionWrapper(ex);
                }
            });
        } catch (LambdaExceptionWrapper ex) {
            throw (CpeValidationException) ex.getCause();
        } finally {
        	builder.reset();
        }
        return software;
    }
    
    /**
     * Attempts to determine the ecosystem based on the vendor, product and
     * targetSw.
     *
     * @param baseEcosystem the base ecosystem
     * @param vendor the vendor
     * @param product the product
     * @param targetSw the target software
     * @return the ecosystem if one is identified
     */
    private String determineEcosystem(String baseEcosystem, String vendor, String product, String targetSw) {
        if ("ibm".equals(vendor) && "java".equals(product)) {
            return "c/c++";
        }
        if ("oracle".equals(vendor) && "vm".equals(product)) {
            return "c/c++";
        }
        if ("*".equals(targetSw) || baseEcosystem != null) {
            return baseEcosystem;
        }
        return targetSw;
    }    
    
    /**
     * Helper method to convert a CpeMatch (generated code used in parsing the
     * NVD JSON) into a CPE object.
     *
     * @param cpe the CPE Match
     * @param cveId the CVE associated with the CPEMatch - used for error
     * reporting
     * @return the resulting CPE object
     * @throws DatabaseException thrown if there is an error converting the
     * CpeMatch into a CPE object
     */
    private Cpe parseCpe(DefCpeMatch cpe, String cveId) throws DatabaseException {
        Cpe parsedCpe;
        try {
            //the replace is a hack as the NVD does not properly escape backslashes in their JSON
            parsedCpe = CpeParser.parse(cpe.getCpe23Uri(), true);
        } catch (CpeParsingException ex) {
            LOGGER.debug("NVD (" + cveId + ") contain an invalid 2.3 CPE: " + cpe.getCpe23Uri());
            if (cpe.getCpe22Uri() != null && !cpe.getCpe22Uri().isEmpty()) {
                try {
                    parsedCpe = CpeParser.parse(cpe.getCpe22Uri(), true);
                } catch (CpeParsingException ex2) {
                    throw new DatabaseException("Unable to parse CPE: " + cpe.getCpe23Uri(), ex);
                }
            } else {
                throw new DatabaseException("Unable to parse CPE: " + cpe.getCpe23Uri(), ex);
            }
        }
        return parsedCpe;
    }    
    
    public int spawnVulnerableSoftware (VulnerableSoftware parsedCpe, String baseEcosystem) {
    	String key = getKey(parsedCpe);
    	
    	int id;
    	synchronized(softwares) {
	    	Integer integer = softwares.get(key);
	    	if(integer != null) {
	    		return integer;
	    	}
	
	    	id = counter.getAndIncrement();

	    	softwares.put(key, id);
    	}
    	
    	String[] row = new String[13];
    	
    	row[0] = Integer.toString(id);
        row[1] = parsedCpe.getPart().getAbbreviation();
        row[2] = parsedCpe.getVendor();
        row[3] = parsedCpe.getProduct();
        row[4] = parsedCpe.getVersion();
        row[5] = parsedCpe.getUpdate();
        row[6] = parsedCpe.getEdition();
        row[7] = parsedCpe.getLanguage();
        row[8] = parsedCpe.getSwEdition();
        row[9] = parsedCpe.getTargetSw();
        row[10] = parsedCpe.getTargetHw();
        row[11] = parsedCpe.getOther();
        row[12] = determineEcosystem(baseEcosystem, parsedCpe.getVendor(), parsedCpe.getProduct(), parsedCpe.getTargetSw());
        
        cpeEntryWriter.writeNext(row);
        
    	return id;
    }

	private String getKey(VulnerableSoftware parsedCpe) {
		StringBuilder builder = new StringBuilder();

    	builder.append(parsedCpe.getPart().getAbbreviation());
    	builder.append(parsedCpe.getVendor());
    	
    	builder.append(parsedCpe.getProduct());
    	builder.append(parsedCpe.getVersion());
    	builder.append(parsedCpe.getUpdate());
    	builder.append(parsedCpe.getEdition());
    	builder.append(parsedCpe.getLanguage());
    	builder.append(parsedCpe.getSwEdition());
    	builder.append(parsedCpe.getTargetSw());
    	builder.append(parsedCpe.getTargetHw());
    	builder.append(parsedCpe.getOther());
    	
    	String key = builder.toString();
		return key;
	}
	
}
