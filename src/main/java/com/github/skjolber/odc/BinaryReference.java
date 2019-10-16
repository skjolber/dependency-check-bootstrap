package com.github.skjolber.odc;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class BinaryReference {

	private byte NAME_FILTER = 0x1;
	private byte URL_FILTER = 0x2;
	private byte SOURCE_FILTER = 0x4;
	
	private int cveId;
	private String name;
	private String url;
	private String source;
	
	public boolean read(DataInputStream in) throws IOException {
		int ch1 = in.read();
		if(ch1 == -1) {
			return false;
		}
		int ch2 = in.read();
		int ch3 = in.read();
		int ch4 = in.read();
		
		this.cveId = ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));

		int filter = in.readByte();

		if( (filter & NAME_FILTER) > 0) {
			this.name = in.readUTF();
		} else {
			this.name = null;
		}
		if( (filter & URL_FILTER) > 0) {
			this.url = in.readUTF();
		} else {
			this.url = null;
		}
		if( (filter & SOURCE_FILTER) > 0) {
			this.source = in.readUTF();
		} else {
			this.source = null;
		}
		return true;
	}
	
	public void write(DataOutputStream out) throws IOException {
		out.writeInt(cveId);
		
		int filter = 0;
		if(name != null) {
			filter |= NAME_FILTER;
		}
		if(url != null) {
			filter |= URL_FILTER;
		}
		if(source != null) {
			filter |= SOURCE_FILTER;
		}
		out.writeByte(filter);
		if(name != null) {
			out.writeUTF(name);
		}
		if(url != null) {
			out.writeUTF(url);
		}
		if(source != null) {
			out.writeUTF(source);
		}
	}

	public int getCveId() {
		return cveId;
	}

	public String getName() {
		return name;
	}

	public String getUrl() {
		return url;
	}

	public String getSource() {
		return source;
	}

	public void setCveId(int cveId) {
		this.cveId = cveId;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public void setSource(String source) {
		this.source = source;
	}
	
}
