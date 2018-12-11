/*
 --------------------------------------------------------------------------------
 SPADE - Support for Provenance Auditing in Distributed Environments.
 Copyright (C) 2015 SRI International

 This program is free software: you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.
 --------------------------------------------------------------------------------
 */

package spade.reporter.audit.artifact;

import java.util.Map;

import spade.reporter.audit.OPMConstants;

public class UnknownIdentifier extends TransientArtifactIdentifier{

	private static final long serialVersionUID = 6511655756054136851L;
	private String fd;
	
	public UnknownIdentifier(String tgid, String tgidTime, String fd){
		super(tgid, tgidTime);
		this.fd = fd;
	}
	
	public String getFD(){
		return fd;
	}
	
	@Override
	public Map<String, String> getAnnotationsMap() {
		Map<String, String> annotations = super.getAnnotationsMap();
		annotations.put(OPMConstants.ARTIFACT_FD, fd);
		return annotations;
	}
	
	public String getSubtype(){
		return OPMConstants.SUBTYPE_UNKNOWN;
	}

	@Override
	public int hashCode(){
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((fd == null) ? 0 : fd.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj){
		if(this == obj)
			return true;
		if(!super.equals(obj))
			return false;
		if(getClass() != obj.getClass())
			return false;
		UnknownIdentifier other = (UnknownIdentifier)obj;
		if(fd == null){
			if(other.fd != null)
				return false;
		}else if(!fd.equals(other.fd))
			return false;
		return true;
	}

	@Override
	public String toString(){
		return "UnknownIdentifier [fd=" + fd + ", tgid=" + getGroupId() + ", tgidTime="
				+ getGroupTime() + "]";
	}
	
}
