/*
 --------------------------------------------------------------------------------
 SPADE - Support for Provenance Auditing in Distributed Environments.
 Copyright (C) 2012 SRI International

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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;

import com.sleepycat.je.Database;
import com.sleepycat.je.DatabaseConfig;
import com.sleepycat.je.DatabaseEntry;
import com.sleepycat.je.Environment;
import com.sleepycat.je.EnvironmentConfig;
import com.sleepycat.je.LockMode;
import com.sleepycat.je.OperationStatus;

/**
 * This class implements the ExternalStore interface and is used in ExternalMemoryMap class
 *
 * @param <V> Serializable object to save in BerkeleyDB
 */

public class BerkeleyDB<V extends Serializable> implements ExternalStore<V> {
	
	private Environment environment;
	private Database database;
	
	private String directoryPath;
	private String databaseName;
	
	private boolean isClosed = false;
	
	protected BerkeleyDB(String directoryPath, String databaseName) throws Exception{
		this.directoryPath = directoryPath;
		this.databaseName = databaseName;
		
		environment = new Environment(new File(directoryPath), getDefaultEnvironmentConfig());
		database = environment.openDatabase(null, databaseName, getDefaultDatabaseConfig());
		
		if(environment == null || database == null){
			throw new Exception("Silently failed to initialize DB");
		}
	}

	private DatabaseConfig getDefaultDatabaseConfig(){
		DatabaseConfig dbConfig = new DatabaseConfig();
		dbConfig.setAllowCreate(true);
		return dbConfig;
	}
	
	private EnvironmentConfig getDefaultEnvironmentConfig(){
		EnvironmentConfig envConfig = new EnvironmentConfig();
		envConfig.setAllowCreate(true);
		return envConfig;
	}
	
	private String getDBPrintableString(){
		return "["+databaseName+"("+directoryPath+")]";
	}
	
	private String getDBClosedErrorMessage(){
		return "DB "+getDBPrintableString()+" is closed";
	}
	
	@Override
	public V get(String key) throws Exception {
		if(isClosed){
			throw new Exception(getDBClosedErrorMessage());
		}else{
			if(key != null){
				DatabaseEntry keyEntry = new DatabaseEntry(key.getBytes());
				DatabaseEntry valueEntry = new DatabaseEntry();
				
			    if(database.get(null, keyEntry, valueEntry, LockMode.DEFAULT) == OperationStatus.SUCCESS){
			        byte[] valueBytes = valueEntry.getData();
			        ByteArrayInputStream byteInputStream = new ByteArrayInputStream(valueBytes);
					ObjectInputStream objectInputStream = new ObjectInputStream(byteInputStream);
					return (V)objectInputStream.readObject();
			    }else{
			        return null;
			    }
			}else{
				return null;
			}
		}
	}

	@Override
	public void put(String key, V value) throws Exception {
		if(isClosed){
			throw new Exception(getDBClosedErrorMessage());
		}else{
			if(key != null && value != null){
				ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
				ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteOutputStream);
				objectOutputStream.writeObject(value);
				objectOutputStream.flush();
				byte[] valueBytes = byteOutputStream.toByteArray(); 
				
				DatabaseEntry keyEntry = new DatabaseEntry(key.getBytes());
				DatabaseEntry valueEntry = new DatabaseEntry(valueBytes);
				database.put(null, keyEntry, valueEntry);
			}
		}
	}

	@Override
	public void remove(String key) throws Exception {
		if(isClosed){
			throw new Exception(getDBClosedErrorMessage());
		}else{
			if(key != null){
			    DatabaseEntry keyEntry = new DatabaseEntry(key.getBytes());
			    database.delete(null, keyEntry);
			}
		}
	}

	/**
	 * NOT IMPLEMENTED YET	
	 */
	@Override
	public void clear() throws Exception {
		//no current implementation
	}
	
	@Override
	public void reopen() throws Exception{
		if(!isClosed){
			throw new Exception("DB "+getDBPrintableString()+" is already open");
		}else{
			environment = new Environment(new File(directoryPath), getDefaultEnvironmentConfig());
			database = environment.openDatabase(null, databaseName, getDefaultDatabaseConfig());
			
			if(environment == null || database == null){
				throw new Exception("Silently failed to reopen DB");
			}
			isClosed = false;
		}
	}
	
	@Override
	public boolean isClosed(){
		return isClosed;
	}
	
	@Override
	public void close() throws Exception{
		if(isClosed){
			throw new Exception(getDBClosedErrorMessage());
		}else{
			isClosed = true;
			if(database != null){
				database.close();
				database = null;
			}
			if(environment != null){
				environment.close();
				environment = null;
			}
		}
	}
	
	@Override
	public void delete() throws Exception{
		if(directoryPath != null){
			try{
				if(FileUtility.doesPathExist(directoryPath)){
					if(!FileUtility.deleteDirectory(directoryPath)){
						throw new Exception();
					}
				}
			}catch(Exception e){
				throw new Exception(e.getMessage() + ". Path deletion failed: " + directoryPath, e);
			}
		}
	}
	
	public BigInteger sizeInBytesOfPersistedData() throws Exception{
		if(directoryPath != null){
			try{
				if(FileUtility.doesPathExist(directoryPath)){
					return FileUtility.getSizeInBytes(directoryPath);
				}else{
					throw new Exception("Does not exist");
				}
			}catch(Exception e){
				throw new Exception(e.getMessage() + ". Failed to get size for path: " + directoryPath, e);
			}
		}else{
			return BigInteger.ZERO;
		}
	}

}
