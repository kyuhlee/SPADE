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
package spade.filter;

import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;

import spade.core.AbstractEdge;
import spade.core.AbstractFilter;
import spade.core.AbstractVertex;
import spade.core.Settings;
import spade.utility.CommonFunctions;
import spade.utility.ExternalMemoryMap;
import spade.utility.FileUtility;
import spade.utility.Hasher;

/**
 * Can be used to check:
 * 1) If Audit reporter outputs a duplicate vertex
 * 2) If Audit reporter outputs an edge whose endpoints haven't been seen
 */
public class AuditSanity extends AbstractFilter{

	private Logger logger = Logger.getLogger(this.getClass().getName());
	
	private ExternalMemoryMap<AbstractVertex, Integer> vertexMap;
	private final String vertexMapId = "AuditSanity[VertexMap]";
	
	public boolean initialize(String arguments){
		String configFilePath = Settings.getDefaultConfigFilePath(this.getClass());
		Map<String, String> configMap = null;
		try{
			configMap = FileUtility.readConfigFileAsKeyValueMap(configFilePath, "=");
		}catch(Throwable t){
			logger.log(Level.SEVERE, "Failed to read config file: " + configFilePath, t);
			return false;
		}
		
		if(configMap == null){
			logger.log(Level.SEVERE, "NULL config map read from file: " + configFilePath);
			return false;
		}else{
			try{
				vertexMap = CommonFunctions.createExternalMemoryMapInstance(vertexMapId, 
						configMap.get("cacheSize"), configMap.get("falsePositiveProb"), 
						configMap.get("expectedElements"), configMap.get("dbParentDir"), 
						configMap.get("dbName"), configMap.get("reportingIntervalSeconds"), 
						configMap.get("dbStoreClassName"),
						new Hasher<AbstractVertex>(){
							@Override
							public String getHash(AbstractVertex t) {
								return DigestUtils.sha256Hex(String.valueOf(t));
							}
						}, true, false, true);
				if(vertexMap != null){
					return true;
				}else{
					logger.log(Level.SEVERE, "Silently failed to initialize external map");
					return false;
				}
			}catch(Exception e){
				logger.log(Level.SEVERE, "Failed to create external map", e);
				return false;
			}
		}
	}
	
	public boolean shutdown(){
		if(vertexMap != null){
			CommonFunctions.closePrintSizeAndDeleteExternalMemoryMap(vertexMapId, vertexMap, true);
			vertexMap = null;
		}
		return true;
	}
	
	@Override
	public void putVertex(AbstractVertex incomingVertex) {
		if(vertexMap.get(incomingVertex) != null){
			logger.log(Level.WARNING, "Duplicate vertex: " + incomingVertex);
		}else{
			vertexMap.put(incomingVertex, 1);
		}
		putInNextFilter(incomingVertex);
	}

	@Override
	public void putEdge(AbstractEdge incomingEdge) {
		AbstractVertex source = incomingEdge.getChildVertex();
		AbstractVertex destination = incomingEdge.getParentVertex();
		
		Integer sourceExists = vertexMap.get(source);
		Integer destinationExists = vertexMap.get(destination);
		
		if(sourceExists == null && destinationExists == null){
			logger.log(Level.WARNING, "Missing source and destination vertices: (" + source + ") -> [" + incomingEdge + "] -> (" + destination + ")");
		}else if(sourceExists == null && destinationExists != null){
			logger.log(Level.WARNING, "Missing source vertex: (" + source + ") -> [" + incomingEdge + "] -> (" + destination + ")");
		}else if(sourceExists != null && destinationExists == null){
			logger.log(Level.WARNING, "Missing destination vertex: (" + source + ") -> [" + incomingEdge + "] -> (" + destination + ")");
		}
		putInNextFilter(incomingEdge);
	}
	
}
