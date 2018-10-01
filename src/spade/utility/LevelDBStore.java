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

import static org.fusesource.leveldbjni.JniDBFactory.factory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;

import org.iq80.leveldb.CompressionType;
import org.iq80.leveldb.DB;
import org.iq80.leveldb.Options;

public class LevelDBStore<V extends Serializable> implements ExternalStore<V>{

	private final String dbName;
	private final String dbDirPath;
	
	private DB db;
	
	private boolean isClosed = false;
	
	protected LevelDBStore(String dbDirPath, String dbName) throws Throwable{
		this.dbDirPath = dbDirPath;
		this.dbName = dbName;
		
        db = factory.open(new File(this.dbDirPath), getDefaultOptions());
        if(db == null){
        	throw new Exception("Silently failed to initialize DB");
        }
	}
	
	private Options getDefaultOptions(){
		Options options = new Options();
        options.createIfMissing(true);
        options.compressionType(CompressionType.NONE);
        return options;
	}
	
	private String getDBPrintableString(){
		return "["+dbName+"("+dbDirPath+")]";
	}
	
	private String getDBClosedErrorMessage(){
		return "DB "+getDBPrintableString()+" is closed";
	}
	
	@Override
	public V get(String key) throws Exception{
		if(isClosed){
			throw new Exception(getDBClosedErrorMessage());
		}else{
			if(key != null){
				byte[] valueBytes = db.get(key.getBytes());
				if(valueBytes != null){
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
	public void put(String key, V value) throws Exception{
		if(isClosed){
			throw new Exception(getDBClosedErrorMessage());
		}else{
			if(key != null && value != null){
				ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
				ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteOutputStream);
				objectOutputStream.writeObject(value);
				objectOutputStream.flush();
				byte[] valueBytes = byteOutputStream.toByteArray(); 
				
				db.put(key.getBytes(), valueBytes);
			}
		}
	}

	@Override
	public void remove(String key) throws Exception{
		if(isClosed){
			throw new Exception(getDBClosedErrorMessage());
		}else{
			if(key != null){
				db.delete(key.getBytes());
			}
		}
	}

	/**
	 * NOT IMPLEMENTED YET	
	 */
	@Override
	public void clear() throws Exception{
		//no current implementation
	}
	
	@Override
	public void reopen() throws Exception{
		if(!isClosed){
			throw new Exception("DB "+getDBPrintableString()+" is already open");
		}else{
			db = factory.open(new File(this.dbDirPath), getDefaultOptions());
			if(db == null){
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
			if(db != null){
				db.close();
				db = null;
			}
		}
	}

	@Override
	public void delete() throws Exception{
		if(dbDirPath != null){
			try{
				if(FileUtility.doesPathExist(dbDirPath)){
					if(!FileUtility.deleteDirectory(dbDirPath)){
						throw new Exception();
					}
				}
			}catch(Exception e){
				throw new Exception(e.getMessage() + ". Path deletion failed: " + dbDirPath, e);
			}
		}
	}
	
	@Override
	public BigInteger sizeInBytesOfPersistedData() throws Exception{
		if(dbDirPath != null){
			try{
				if(FileUtility.doesPathExist(dbDirPath)){
					return FileUtility.getSizeInBytes(dbDirPath);
				}else{
					throw new Exception("Does not exist");
				}
			}catch(Exception e){
				throw new Exception(e.getMessage() + ". Failed to get size for path: " + dbDirPath, e);
			}
		}else{
			return BigInteger.ZERO;
		}
	}
	
}
