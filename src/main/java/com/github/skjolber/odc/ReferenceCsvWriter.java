package com.github.skjolber.odc;



import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.analyzer.AbstractNpmAnalyzer;
import org.owasp.dependencycheck.analyzer.CMakeAnalyzer;
import org.owasp.dependencycheck.analyzer.ComposerLockAnalyzer;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.analyzer.NodeAuditAnalyzer;
import org.owasp.dependencycheck.analyzer.PythonPackageAnalyzer;
import org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer;
import org.owasp.dependencycheck.analyzer.RubyGemspecAnalyzer;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.Reference;

import com.opencsv.CSVWriter;
import com.opencsv.ICSVWriter;

public class ReferenceCsvWriter extends AbstractWriter {

	private ICSVWriter writer;
	private Path path;
	
	public ReferenceCsvWriter(Path directory, boolean noop) {
		super(noop);
		
		path = directory.resolve("owasp.reference.csv");
	}	

    public String write(int vulnerabilityId, DefCveItem cve, String description) {
        String ecosystem = determineEcoSystem(cve, description);
        
        String[] row = new String[4];
        row[0] = Integer.toString(vulnerabilityId);
        
        for (Reference r : cve.getCve().getReferences().getReferenceData()) {
            row[1] = r.getName();
            row[2] = r.getUrl();
            row[3] = r.getRefsource();
            
            writer.writeNext(row);
        }
        return ecosystem;
    }

	private String determineEcoSystem(DefCveItem cve, String description) {
		String ecosystem = determineBaseEcosystem(description);
        if (ecosystem == null) {
            for (Reference r : cve.getCve().getReferences().getReferenceData()) {
                if (r.getUrl().contains("elixir-security-advisories")) {
                    ecosystem = "elixir";
                } else if (r.getUrl().contains("ruby-lang.org")) {
                    ecosystem = RubyGemspecAnalyzer.DEPENDENCY_ECOSYSTEM;
                } else if (r.getUrl().contains("python.org")) {
                    ecosystem = PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM;
                } else if (r.getUrl().contains("drupal.org")) {
                    ecosystem = PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM;
                } else if (r.getUrl().contains("npm")) {
                    ecosystem = NodeAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
                } else if (r.getUrl().contains("nodejs.org")) {
                    ecosystem = NodeAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
                } else if (r.getUrl().contains("nodesecurity.io")) {
                    ecosystem = NodeAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
                }
            }
        }
		return ecosystem;
	}
    

	public void open() throws IOException {
		writer = createWriter(path);
		writer.writeNext(new String[]{"cveid", "name", "url", "source"});
	}
	
	public void close() throws IOException {
		if(writer != null) {
			writer.close(); 
		}
	}

	public String getSql()  {
		try {
			return String.format(IOUtils.toString(getClass().getResourceAsStream("/csv-sql/reference.sql"), StandardCharsets.UTF_8), path.toAbsolutePath().toString());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

    private String determineBaseEcosystem(String description) {
        if (description == null) {
            return null;
        }
        int idx = StringUtils.indexOfIgnoreCase(description, ".php");
        if ((idx > 0 && (idx + 4 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 4))))
                || StringUtils.containsIgnoreCase(description, "wordpress")
                || StringUtils.containsIgnoreCase(description, "drupal")
                || StringUtils.containsIgnoreCase(description, "joomla")
                || StringUtils.containsIgnoreCase(description, "moodle")
                || StringUtils.containsIgnoreCase(description, "typo3")) {
            return ComposerLockAnalyzer.DEPENDENCY_ECOSYSTEM;
        }
        if (StringUtils.containsIgnoreCase(description, " npm ")
                || StringUtils.containsIgnoreCase(description, " node.js")) {
            return AbstractNpmAnalyzer.NPM_DEPENDENCY_ECOSYSTEM;
        }
        idx = StringUtils.indexOfIgnoreCase(description, ".pm");
        if (idx > 0 && (idx + 3 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 3)))) {
            return "perl";
        } else {
            idx = StringUtils.indexOfIgnoreCase(description, ".pl");
            if (idx > 0 && (idx + 3 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 3)))) {
                return "perl";
            }
        }
        idx = StringUtils.indexOfIgnoreCase(description, ".java");
        if (idx > 0 && (idx + 5 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 5)))) {
            return JarAnalyzer.DEPENDENCY_ECOSYSTEM;
        } else {
            idx = StringUtils.indexOfIgnoreCase(description, ".jsp");
            if (idx > 0 && (idx + 4 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 4)))) {
                return JarAnalyzer.DEPENDENCY_ECOSYSTEM;
            }
        }
        if (StringUtils.containsIgnoreCase(description, " grails ")) {
            return JarAnalyzer.DEPENDENCY_ECOSYSTEM;
        }

        idx = StringUtils.indexOfIgnoreCase(description, ".rb");
        if (idx > 0 && (idx + 3 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 3)))) {
            return RubyBundleAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
        }
        if (StringUtils.containsIgnoreCase(description, "ruby gem")) {
            return RubyBundleAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
        }

        idx = StringUtils.indexOfIgnoreCase(description, ".py");
        if ((idx > 0 && (idx + 3 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 3))))
                || StringUtils.containsIgnoreCase(description, "django")) {
            return PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM;
        }

        if (StringUtils.containsIgnoreCase(description, "buffer overflow")
                && !StringUtils.containsIgnoreCase(description, "android")) {
            return CMakeAnalyzer.DEPENDENCY_ECOSYSTEM;
        }
        idx = StringUtils.indexOfIgnoreCase(description, ".c");
        if (idx > 0 && (idx + 2 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 2)))) {
            return CMakeAnalyzer.DEPENDENCY_ECOSYSTEM;
        } else {
            idx = StringUtils.indexOfIgnoreCase(description, ".cpp");
            if (idx > 0 && (idx + 4 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 4)))) {
                return CMakeAnalyzer.DEPENDENCY_ECOSYSTEM;
            } else {
                idx = StringUtils.indexOfIgnoreCase(description, ".h");
                if (idx > 0 && (idx + 2 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 2)))) {
                    return CMakeAnalyzer.DEPENDENCY_ECOSYSTEM;
                }
            }
        }
        return null;
    }
    	
}
