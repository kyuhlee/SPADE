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

import java.util.HashMap;
import java.util.Map;

import spade.reporter.audit.OPMConstants;

public abstract class TransientArtifactIdentifier extends ArtifactIdentifier{

	private static final long serialVersionUID = -4218714322311264614L;

	private String groupId, groupTime;
	
	public TransientArtifactIdentifier(String groupId, String groupTime){
		this.groupId = groupId;
		this.groupTime = groupTime;
	}

	public String getGroupId(){
		return groupId;
	}
	
	public String getGroupTime(){
		return groupTime;
	}
	
	@Override
	public Map<String, String> getAnnotationsMap(){
		Map<String, String> map = new HashMap<String, String>();
		map.put(OPMConstants.ARTIFACT_TGID, groupId);
		map.put(OPMConstants.ARTIFACT_TIME, groupTime);
		return map;
	}

	@Override
	public int hashCode(){
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((groupId == null) ? 0 : groupId.hashCode());
		result = prime * result + ((groupTime == null) ? 0 : groupTime.hashCode());
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
		TransientArtifactIdentifier other = (TransientArtifactIdentifier)obj;
		if(groupId == null){
			if(other.groupId != null)
				return false;
		}else if(!groupId.equals(other.groupId))
			return false;
		if(groupTime == null){
			if(other.groupTime != null)
				return false;
		}else if(!groupTime.equals(other.groupTime))
			return false;
		return true;
	}

}
