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

import spade.reporter.audit.OPMConstants;

public class UnnamedUnixSocketPairIdentifier extends FdPairIdentifier{

	private static final long serialVersionUID = 9009374043657988074L;

	public UnnamedUnixSocketPairIdentifier(String tgid, String tgidTime, String fd0, String fd1){
		super(tgid, tgidTime, fd0, fd1);
	}
	
	@Override
	public String getFd0Key(){ return OPMConstants.ARTIFACT_FD0; }
	
	@Override
	public String getFd1Key(){ return OPMConstants.ARTIFACT_FD1; }
	
	@Override
	public String getSubtype() { return OPMConstants.SUBTYPE_UNNAMED_UNIX_SOCKET_PAIR; }

	@Override
	public String toString(){
		return "UnnamedUnixSocketPairIdentifier [fd0=" + fd0 + ", fd1=" + fd1 + ", tgid=" + getGroupId()
				+ ", tgidTime=" + getGroupTime() + "]";
	}
}
