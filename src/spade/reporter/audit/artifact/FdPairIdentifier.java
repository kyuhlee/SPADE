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

public abstract class FdPairIdentifier extends TransientArtifactIdentifier {

	private static final long serialVersionUID = -4930748608565367219L;
	
	public final String fd0, fd1;
	
	public FdPairIdentifier(String tgid, String processTime, String fd0, String fd1){
		super(tgid, processTime);
		this.fd0 = fd0;
		this.fd1 = fd1;
	}
	
	protected abstract String getFd0Key();
	protected abstract String getFd1Key();
	
	@Override
	public Map<String, String> getAnnotationsMap(){ // FDs to be added by child classes
		Map<String, String> map = super.getAnnotationsMap();
		map.put(getFd0Key(), String.valueOf(fd0));
		map.put(getFd1Key(), String.valueOf(fd1));
		return map;
	}

	@Override
	public int hashCode(){
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((fd0 == null) ? 0 : fd0.hashCode());
		result = prime * result + ((fd1 == null) ? 0 : fd1.hashCode());
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
		FdPairIdentifier other = (FdPairIdentifier)obj;
		if(fd0 == null){
			if(other.fd0 != null)
				return false;
		}else if(!fd0.equals(other.fd0))
			return false;
		if(fd1 == null){
			if(other.fd1 != null)
				return false;
		}else if(!fd1.equals(other.fd1))
			return false;
		return true;
	}

	public abstract String toString();
}
