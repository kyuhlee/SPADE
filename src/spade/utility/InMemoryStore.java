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
package spade.utility;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class InMemoryStore<V extends Serializable> implements ExternalStore<V>{

	private final String dbName; // the name
	private final String dbNamespace; // usually the directory
	
	private final Map<String, V> map = new HashMap<String, V>();
	
	protected InMemoryStore(String dbNamespace, String dbName){
		this.dbName = dbName;
		this.dbNamespace = dbNamespace;
	}
	
	@Override
	public V get(String key) throws Exception{
		return map.get(key);
	}

	@Override
	public void put(String key, V value) throws Exception{
		map.put(key, value);
	}

	@Override
	public void remove(String key) throws Exception{
		map.remove(key);
	}

	@Override
	public void clear() throws Exception{
		map.clear();
	}

	@Override
	public void reopen() throws Exception{
		// NOT APPLICABLE
	}

	@Override
	public boolean isClosed(){
		return false;
	}

	@Override
	public void close() throws Exception{
		// NOT APPLICABLE
	}

	@Override
	public void delete() throws Exception{
		map.clear();
	}

	@Override
	public BigInteger sizeInBytesOfPersistedData() throws Exception{
		return BigInteger.ZERO;
	}

}
