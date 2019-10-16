/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package com.github.skjolber.odc;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;

import org.owasp.dependencycheck.data.nvd.json.CpeMatchStreamCollector;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.NodeFlatteningCollector;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import us.springett.parsers.cpe.exceptions.CpeValidationException;

public final class NvdCveParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NvdCveParser.class);
    /**
     * The filter for 2.3 CPEs in the CVEs - we don't import unless we get a
     * match.
     */
    private final String cpeStartsWithFilter;
    
    private final VulnerabilityCsvWriter vulnerabilityWriter;
    private final CweEntryWriter cweEntryWriter;
    private final SoftwareCsvWriter softwareWriter;

    private Path directory;
	private BinaryReferenceWriter binaryReferenceWriter;
    

    public NvdCveParser(Path directory, IdSpace idSpace, Settings settings, CpeCache cpes) throws IOException {
    	this.directory = directory;
        this.cpeStartsWithFilter = settings.getString(Settings.KEYS.CVE_CPE_STARTS_WITH_FILTER, "cpe:2.3:a:");
        
        this.vulnerabilityWriter = new VulnerabilityCsvWriter(directory, idSpace.next());
		
        this.cweEntryWriter = new CweEntryWriter(directory);
        this.binaryReferenceWriter = new BinaryReferenceWriter(directory);
        this.softwareWriter = new SoftwareCsvWriter(directory, settings, cpes);
    }

    /**
     * Parses the NVD JSON file and inserts/updates data into the database.
     *
     * @param file the NVD JSON file to parse
     * @throws UpdateException thrown if the file could not be read
     * @throws IOException 
     * @throws CpeValidationException 
     * @throws FileNotFoundException 
     */

    public void parse(URL url) throws Exception {
    	long time = System.currentTimeMillis();

        try (InputStream in = url.openStream()) {
        	parse(in);
        }
        System.out.println("Parsed and generated CSV in " + (System.currentTimeMillis() - time) + "ms for " + directory);

    }
    
    public void parse(Path path) throws Exception {
    	long time = System.currentTimeMillis();
    	
    	try (InputStream fin = Files.newInputStream(path)) {
	        parse(fin);
	    }
        System.out.println("Parsed and generated CSV in " + (System.currentTimeMillis() - time) + "ms for " + directory);
    }

	private void parse(InputStream fin) throws Exception {
		try (InputStream in = new GZIPInputStream(fin);
		        InputStreamReader isr = new InputStreamReader(in, UTF_8);
		        JsonReader reader = new JsonReader(isr)) {
			
		    Gson gson = new GsonBuilder().create();

		    reader.beginObject();

		    while (reader.hasNext() && !JsonToken.BEGIN_ARRAY.equals(reader.peek())) {
		        reader.skipValue();
		    }
		    reader.beginArray();
		    
		    vulnerabilityWriter.open();
			cweEntryWriter.open();
			binaryReferenceWriter.open();
			softwareWriter.open();
			
		    while (reader.hasNext()) {
		        final DefCveItem cve = gson.fromJson(reader, DefCveItem.class);

		        if (testCveCpeStartWithFilter(cve)) {
		            final String description = cve.getCve().getDescription().getDescriptionData().stream().filter((desc)
		                    -> "en".equals(desc.getLang())).map(d
		                    -> d.getValue()).collect(Collectors.joining(" "));

		        	int vulnerabilityId = vulnerabilityWriter.write(cve, description);
		        	
		        	cweEntryWriter.write(vulnerabilityId, cve);
		        	
		        	String ecoSystem = binaryReferenceWriter.write(vulnerabilityId, cve, description);
		        	
		        	softwareWriter.write(vulnerabilityId, cve, ecoSystem);
		        }
		    }
		    
		    vulnerabilityWriter.close();
		    cweEntryWriter.close();
		    binaryReferenceWriter.close();
		    softwareWriter.close();
		}
	}
    
    public List<String> getSql() throws Exception {
    	List<String> list = new ArrayList<>();
    	
    	list.add(vulnerabilityWriter.getSql());
    	list.add(cweEntryWriter.getSql());
    	
    	list.add(binaryReferenceWriter.getSql());
    	//list.add(referenceWriter.getSql());
    	
    	list.addAll(softwareWriter.getVulnerableSoftwareSql());

    	list.add(softwareWriter.getCpeEntrySql());

    	return list;
    }
    

    /**
     * Tests the CVE's CPE entries against the starts with filter. In general
     * this limits the CVEs imported to just application level vulnerabilities.
     *
     * @param cve the CVE entry to examine
     * @return <code>true</code> if the CVE affects CPEs identified by the
     * configured CPE Starts with filter
     */
    protected boolean testCveCpeStartWithFilter(final DefCveItem cve) {
        //cycle through to see if this is a CPE we care about (use the CPE filters
        return cve.getConfigurations().getNodes().stream()
                .collect(new NodeFlatteningCollector())
                .collect(new CpeMatchStreamCollector())
                .anyMatch(cpe -> cpe.getCpe23Uri().startsWith(cpeStartsWithFilter));
    }
    
}
