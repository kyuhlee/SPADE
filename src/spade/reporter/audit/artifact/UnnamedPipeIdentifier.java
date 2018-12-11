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

public class UnnamedPipeIdentifier extends FdPairIdentifier{

	private static final long serialVersionUID = -4888235272900911375L;
	
	/**
	 * @param tgid owner process's thread group id
	 * @param tgidTime process's thread group start or seen time
	 * @param fd0 read end of the pipe
	 * @param fd1 write end of the pipe
	 */
	public UnnamedPipeIdentifier(String tgid, String tgidTime, String fd0, String fd1){
		super(tgid, tgidTime, fd0, fd1);
	}

	@Override
	public String getSubtype(){ return OPMConstants.SUBTYPE_UNNAMED_PIPE; }
	
	@Override
	public String getFd0Key(){ return OPMConstants.ARTIFACT_READ_FD; }
	
	@Override
	public String getFd1Key(){ return OPMConstants.ARTIFACT_WRITE_FD; }

	@Override
	public String toString(){
		return "UnnamedPipeIdentifier [fd0=" + fd0 + ", fd1=" + fd1 + ", tgid=" + getGroupId()
				+ ", tgidTime=" + getGroupTime() + "]";
	}
}
