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

import java.math.BigInteger;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;

import spade.core.Settings;
import spade.edge.opm.WasDerivedFrom;
import spade.reporter.Audit;
import spade.reporter.audit.Globals;
import spade.reporter.audit.OPMConstants;
import spade.utility.CommonFunctions;
import spade.utility.ExternalMemoryMap;
import spade.utility.FileUtility;
import spade.utility.Hasher;
import spade.vertex.opm.Artifact;

public class ArtifactManager{

	private static final Logger logger = Logger.getLogger(ArtifactManager.class.getName());
	
	private static final String 
			CONFIG_KEY_PARENT_DIR = "parentdir",
			
//			CONFIG_KEY_PERSISTENT_SUB_DIR = "persistentsubdir",
			CONFIG_KEY_PERSISTENT_DB_NAME = "persistentdbname",
			CONFIG_KEY_PERSISTENT_CACHE_SIZE = "persistentcachesize",
			CONFIG_KEY_PERSISTENT_BF_FP_PROB = "persistentbffpp",
			CONFIG_KEY_PERSISTENT_BF_EXPECTED_ELEMENTS = "persistentbfexpectedelements",
			CONFIG_KEY_PERSISTENT_REPORTING_INTERVAL_SECONDS = "persistentreportinginterval",
			CONFIG_KEY_PERSISTENT_STORE_CLASS_NAME = "persistentdbstoreclassname",
			
//			CONFIG_KEY_TRANSIENT_SUB_DIR_PREFIX = "transientsubdirprefix",
			CONFIG_KEY_TRANSIENT_DB_NAME_PREFIX = "transientdbnameprefix",
			CONFIG_KEY_TRANSIENT_CACHE_SIZE = "transientcachesize",
			CONFIG_KEY_TRANSIENT_BF_FP_PROB = "transientbffpp",
			CONFIG_KEY_TRANSIENT_BF_EXPECTED_ELEMENTS = "transientbfexpectedelements",
			CONFIG_KEY_TRANSIENT_REPORTING_INTERVAL_SECONDS = "transientreportinginterval",
			CONFIG_KEY_TRANSIENT_STORE_CLASS_NAME = "transientdbstoreclassname",
			CONFIG_KEY_MAX_OPEN_RETRY_COUNT = "maxopenretries";
	
	private static final String[] mandatoryConfigKeys = {CONFIG_KEY_PARENT_DIR, //CONFIG_KEY_PERSISTENT_SUB_DIR, 
			CONFIG_KEY_PERSISTENT_DB_NAME, CONFIG_KEY_PERSISTENT_CACHE_SIZE, CONFIG_KEY_PERSISTENT_BF_FP_PROB,
			CONFIG_KEY_PERSISTENT_BF_EXPECTED_ELEMENTS, CONFIG_KEY_PERSISTENT_BF_EXPECTED_ELEMENTS,
			CONFIG_KEY_PERSISTENT_REPORTING_INTERVAL_SECONDS, CONFIG_KEY_PERSISTENT_STORE_CLASS_NAME,
			//CONFIG_KEY_TRANSIENT_SUB_DIR_PREFIX, 
			CONFIG_KEY_TRANSIENT_DB_NAME_PREFIX, CONFIG_KEY_TRANSIENT_CACHE_SIZE, CONFIG_KEY_TRANSIENT_BF_FP_PROB,
			CONFIG_KEY_TRANSIENT_BF_EXPECTED_ELEMENTS, CONFIG_KEY_TRANSIENT_REPORTING_INTERVAL_SECONDS,
			CONFIG_KEY_TRANSIENT_STORE_CLASS_NAME, CONFIG_KEY_MAX_OPEN_RETRY_COUNT};
	
	private String configParentDir, 
	
			//configPersistentSubDir, 
			configPersistentDbName, configPersistentCacheSize,
			configPersistentBloomfilterFalsePositiveProb, configPersistentBloomfilterExpectedElements,
			configPersistentReportingIntervalSeconds, configPersistentStoreClassName,
			
			//configTransientSubDirPrefix, 
			configTransientDbNamePrefix, configTransientCacheSize, 
			configTransientBloomfilterFalsePositiveProb, configTransientBloomfilterExpectedElements,
			configTransientReportingIntervalSeconds, configTransientStoreClassName;
	private int maxRetryCount;
	
	private long IO_SLEEP_WAIT_MS = 50;
	
	private final Hasher<ArtifactIdentifier> artifactIdentifierHasher = new Hasher<ArtifactIdentifier>(){
		@Override
		public String getHash(ArtifactIdentifier t){
			if(t != null){
				Map<String, String> annotations = t.getAnnotationsMap();
				String subtype = t.getSubtype();
				String stringToHash = String.valueOf(annotations) + "," + String.valueOf(subtype);
				return DigestUtils.sha256Hex(stringToHash);
			}else{
				return DigestUtils.sha256Hex("(null)");
			}
		}
	};
	
	private final Audit reporter;
	
	private final Map<Class<? extends ArtifactIdentifier>, ArtifactConfig> artifactConfigs;
	
	private final String getTransientArtifactsMapId(String processId){
		return "Audit[TransientArtifactsMap("+processId+")]";
	}
	
	private final String getTransientArtifactsMapDbName(String processId){
		return configTransientDbNamePrefix + processId;
	}
	
	private final String getTransientArtifactsMapSubDirPath(String processId){
		return configParentDir;// + File.separator + configTransientSubDirPrefix + processId;
	}
	
	private final String persistentArtifactsMapId = "Audit[PersistentArtifactsMap]";
	private ExternalMemoryMap<ArtifactIdentifier, ArtifactState> persistentArtifactsMap;
	
	// Group id -> external memory map
	private Map<String, ExternalMemoryMap<ArtifactIdentifier, ArtifactState>> closedTransientArtifactsMaps = 
			new HashMap<String, ExternalMemoryMap<ArtifactIdentifier, ArtifactState>>();
	// Group id -> (external memory map, last accessed time)
	private Map<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>> openTransientArtifactsMaps = 
			new HashMap<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>>();
	
	public ArtifactManager(Audit reporter, Globals globals) throws Throwable{
		if(reporter == null){
			throw new IllegalArgumentException("NULL Audit reporter");
		}
		if(globals == null){
			throw new IllegalArgumentException("NULL Globals object");
		}
		this.reporter = reporter;
		artifactConfigs = getArtifactConfig(globals);
		if(globals.keepingArtifactPropertiesMap){
			initConfigFromDefaultConfigFile();
			validateTransientArtifactsMapProperties();
			initPeristentArtifactsMap();
		}else{
			persistentArtifactsMap = null;
		}
	}
	
	private boolean validateTransientArtifactsMapProperties() throws Exception{
		String transientId = "ArgsTest";
		// Never returns false. Either exception or true.
		return CommonFunctions.validateExternalMemoryArguments(getTransientArtifactsMapId(transientId), 
				configTransientCacheSize, configTransientBloomfilterFalsePositiveProb, 
				configTransientBloomfilterExpectedElements, 
				getTransientArtifactsMapSubDirPath(transientId), getTransientArtifactsMapDbName(transientId), 
				configTransientReportingIntervalSeconds, configTransientStoreClassName);
	}
	
	private void initPeristentArtifactsMap() throws Exception{
		String dirPath = configParentDir;// + File.separator + configPersistentSubDir;
		persistentArtifactsMap = CommonFunctions.createExternalMemoryMapInstance(persistentArtifactsMapId, 
				configPersistentCacheSize, configPersistentBloomfilterFalsePositiveProb, 
				configPersistentBloomfilterExpectedElements, dirPath,
				configPersistentDbName, configPersistentReportingIntervalSeconds, configPersistentStoreClassName,
				artifactIdentifierHasher, true, false
		);
	}
	
	private ExternalMemoryMap<ArtifactIdentifier, ArtifactState> initTransientArtifactsMap(String processId) throws Exception{
		String mapId = getTransientArtifactsMapId(processId);
		String dbName = getTransientArtifactsMapDbName(processId);
		String dirPath = getTransientArtifactsMapSubDirPath(processId);
		return CommonFunctions.createExternalMemoryMapInstance(mapId, 
				configTransientCacheSize, configTransientBloomfilterFalsePositiveProb, 
				configTransientBloomfilterExpectedElements, dirPath,
				dbName, configTransientReportingIntervalSeconds, configTransientStoreClassName,
				artifactIdentifierHasher, false, true
		);
	}
	
	private void initConfigFromDefaultConfigFile() throws Exception{
		String filePath = Settings.getDefaultConfigFilePath(this.getClass());
		Map<String, String> configMap = FileUtility.readConfigFileAsKeyValueMap(filePath, "=");
		for(String configKey : mandatoryConfigKeys){
			if(configMap.get(configKey) == null){
				throw new Exception("Missing key '"+configKey+"' in default config file");
			}
		}
		
		Integer maxRetryCountInt = CommonFunctions.parseInt(configMap.get(CONFIG_KEY_MAX_OPEN_RETRY_COUNT), null);
		if(maxRetryCountInt == null){
			throw new Exception("Invalid value for key '"+CONFIG_KEY_MAX_OPEN_RETRY_COUNT+"' in default config file");
		}else{
			if(maxRetryCountInt < 0){
				throw new Exception("Only non-negative values allowed for key '"+CONFIG_KEY_MAX_OPEN_RETRY_COUNT+"' in default config file");
			}else{
				maxRetryCount = maxRetryCountInt;
			}
		}
		
		// All keys found
		configParentDir = configMap.get(CONFIG_KEY_PARENT_DIR);
		
		//configPersistentSubDir = configMap.get(CONFIG_KEY_PERSISTENT_SUB_DIR);
		configPersistentDbName = configMap.get(CONFIG_KEY_PERSISTENT_DB_NAME);
		configPersistentCacheSize = configMap.get(CONFIG_KEY_PERSISTENT_CACHE_SIZE);
		configPersistentBloomfilterFalsePositiveProb = configMap.get(CONFIG_KEY_PERSISTENT_BF_FP_PROB);
		configPersistentBloomfilterExpectedElements = configMap.get(CONFIG_KEY_PERSISTENT_BF_EXPECTED_ELEMENTS);
		configPersistentReportingIntervalSeconds = configMap.get(CONFIG_KEY_PERSISTENT_REPORTING_INTERVAL_SECONDS);
		configPersistentStoreClassName = configMap.get(CONFIG_KEY_PERSISTENT_STORE_CLASS_NAME);
		
		//configTransientSubDirPrefix = configMap.get(CONFIG_KEY_TRANSIENT_SUB_DIR_PREFIX);
		configTransientDbNamePrefix = configMap.get(CONFIG_KEY_TRANSIENT_DB_NAME_PREFIX);
		configTransientCacheSize = configMap.get(CONFIG_KEY_TRANSIENT_CACHE_SIZE);
		configTransientBloomfilterFalsePositiveProb = configMap.get(CONFIG_KEY_TRANSIENT_BF_FP_PROB);
		configTransientBloomfilterExpectedElements = configMap.get(CONFIG_KEY_TRANSIENT_BF_EXPECTED_ELEMENTS);
		configTransientReportingIntervalSeconds = configMap.get(CONFIG_KEY_TRANSIENT_REPORTING_INTERVAL_SECONDS);
		configTransientStoreClassName = configMap.get(CONFIG_KEY_TRANSIENT_STORE_CLASS_NAME);
		
	}
	
	private Map<Class<? extends ArtifactIdentifier>, ArtifactConfig> getArtifactConfig(Globals globals){
		Map<Class<? extends ArtifactIdentifier>, ArtifactConfig> map = 
				new HashMap<Class<? extends ArtifactIdentifier>, ArtifactConfig>();
		map.put(BlockDeviceIdentifier.class, 
				new ArtifactConfig(true, globals.epochs, globals.versions, globals.permissions, true, true, true));
		map.put(CharacterDeviceIdentifier.class, 
				new ArtifactConfig(true, globals.epochs, globals.versions, globals.permissions, true, true, true));
		map.put(DirectoryIdentifier.class, 
				new ArtifactConfig(true, globals.epochs, globals.versions, globals.permissions, true, true, true));
		map.put(FileIdentifier.class, 
				new ArtifactConfig(true, globals.epochs, globals.versions, globals.permissions, 
						true, globals.versionFiles, true));
		map.put(LinkIdentifier.class, 
				new ArtifactConfig(true, globals.epochs, globals.versions, globals.permissions, true, true, true));
		map.put(NamedPipeIdentifier.class, 
				new ArtifactConfig(true, globals.epochs, globals.versions, globals.permissions, 
						true, globals.versionNamedPipes, true));
		map.put(NetworkSocketIdentifier.class, 
				new ArtifactConfig(true, globals.epochs, globals.versions, false, 
						true, globals.versionNetworkSockets, false));
		map.put(UnixSocketIdentifier.class, 
				new ArtifactConfig(globals.unixSockets, globals.epochs, globals.versions, globals.permissions, 
						true, globals.versionUnixSockets, true));

		// Transient ones below
		map.put(MemoryIdentifier.class, new ArtifactConfig(true, false, globals.versions, false, false, 
				globals.versionMemorys, false));
		map.put(UnknownIdentifier.class, new ArtifactConfig(true, globals.epochs, globals.versions, false, 
						true, globals.versionUnknowns, false));
		map.put(UnnamedNetworkSocketPairIdentifier.class, 
				new ArtifactConfig(true, globals.epochs, globals.versions, false, true, true, false));
		map.put(UnnamedPipeIdentifier.class, new ArtifactConfig(true, globals.epochs, globals.versions, false, 
						true, globals.versionUnnamedPipes, false));
		map.put(UnnamedUnixSocketPairIdentifier.class, new ArtifactConfig(true, globals.epochs, globals.versions, false, 
						true, globals.versionUnnamedUnixSocketPairs, false));
		return map;
	}
	
	private boolean outputArtifact(ArtifactIdentifier identifier){
		return artifactConfigs.get(identifier.getClass()).output;
	}
	
	private boolean hasEpoch(ArtifactIdentifier identifier){
		return artifactConfigs.get(identifier.getClass()).hasEpoch;
	}
	
	private boolean hasVersion(ArtifactIdentifier identifier){
		return artifactConfigs.get(identifier.getClass()).hasVersion;
	}
	
	private boolean hasPermissions(ArtifactIdentifier identifier){
		return artifactConfigs.get(identifier.getClass()).hasPermissions;
	}
	
	private boolean isEpochUpdatable(ArtifactIdentifier identifier){
		return artifactConfigs.get(identifier.getClass()).canBeCreated;
	}
	
	private boolean isVersionUpdatable(ArtifactIdentifier identifier){
		// Special checks
		if(identifier instanceof PathIdentifier){
			PathIdentifier pathIdentifier = (PathIdentifier)identifier;
			String path = pathIdentifier.getPath();
			if(path.startsWith("/dev/")){
				return false;
			}
		}
		return artifactConfigs.get(identifier.getClass()).canBeVersioned;
	}
	
	private boolean isPermissionsUpdatable(ArtifactIdentifier identifier){
		return artifactConfigs.get(identifier.getClass()).canBePermissioned;
	}
	
	/**
	 * If identifier is subclass of TransientArtifactIdentifer then:
	 * 		
	 * 		Get group id from the identifier
	 * 		If opened map not found for the group id:
	 * 			Find the map for group id in the closed maps map
	 * 			Try to open the map for this group id
	 * 			Get the opened map for this group id. If null then return the persistent one. else the opened one.
	 * 		else:
	 * 			Updated the access time for the group id in the opened maps map
	 * 			return the found opened map
	 * 		
	 * else:
	 * 		return the persistent artifacts map
	 * 
	 * @param identifier artifact identifier
	 * @return
	 */
	private ExternalMemoryMap<ArtifactIdentifier, ArtifactState> getResolvedArtifactMap(ArtifactIdentifier identifier){
		if(identifier instanceof TransientArtifactIdentifier){
			TransientArtifactIdentifier transientIdentifier = (TransientArtifactIdentifier)(identifier);
			String processId = transientIdentifier.getGroupId();
			SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long> openTransientMapEntry = 
					openTransientArtifactsMaps.get(processId);
			
			if(openTransientMapEntry == null){
				// Check if it exists in closed
				ExternalMemoryMap<ArtifactIdentifier, ArtifactState> closedTransientMap = 
						closedTransientArtifactsMaps.get(processId);
				
				openTransientMap(processId, closedTransientMap);
				
				openTransientMapEntry = openTransientArtifactsMaps.get(processId);
				if(openTransientMapEntry == null || openTransientMapEntry.getKey() == null){
					logger.log(Level.SEVERE, "Using persistent artifacts map. Garbarge collection will fail. "
							+ "Failed to open transient map for processId: " + processId);
					return persistentArtifactsMap;
				}else{
					return openTransientMapEntry.getKey();
				}
			}else{
				// Was in open and is open
				// If exists in open then update the access time and return the map.
				long newAccessTime = System.nanoTime();
				openTransientMapEntry.setValue(newAccessTime);
				return openTransientMapEntry.getKey();
			}
		}else{
			return persistentArtifactsMap;
		}
	}
	
	/**
	 * while not opened the required one:
	 * 		if closedtransientmap is null then try to create a new map
	 * 		if closedtransientmap is NOT null then try to open the existing (but closed) map. If reopened then remove from closed.
	 * 		if no exception then add the opened one to the open maps map
	 * 		if exception then check retries
	 * 		if retries exhausted stop trying to close existing one in order to open the new one
	 * 		if retries NOT exhausted then find the least recently used open one and try to close it
	 * 		try the above from the top again
	 * 
	 * @param processId
	 * @param closedTransientMap
	 */
	private void openTransientMap(String processId, ExternalMemoryMap<ArtifactIdentifier, ArtifactState> closedTransientMap){
		int retryCount = 0;
		
		List<Map.Entry<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>>> list = null;
		
		ExternalMemoryMap<ArtifactIdentifier, ArtifactState> transientMap = null;
		while(transientMap == null){
			try{
				if(closedTransientMap == null){
					transientMap = initTransientArtifactsMap(processId);
				}else{
					closedTransientMap.reopenExternalStore();
					transientMap = closedTransientMap;
					closedTransientArtifactsMaps.remove(processId);
				}
				// If successfully opened i.e. no exception
				if(!transientMap.isExternalStoreClosed()){
					openTransientArtifactsMaps.put(processId, 
							new SimpleEntry<ExternalMemoryMap<ArtifactIdentifier,ArtifactState>, Long>(
									transientMap, System.nanoTime()));
				}else{
					throw new Exception("Silently failed to open external store for processId: " + processId);
				}
			}catch(Throwable t){
				// org.fusesource.leveldbjni.internal.NativeDB$DBException
				// com.sleepycat.je.EnvironmentFailureException
				// Failed to open
				if(retryCount > maxRetryCount){
					logger.log(Level.SEVERE, 
							retryCount + " out of " + maxRetryCount + " retries exhausted to open transient artifacts map for "
									+ "processId: " + processId, t);
					break;
				}else{
					// retry. continue.
					// close the least recently accessed on
					if(list == null){
						list = new ArrayList<>(openTransientArtifactsMaps.entrySet());
						Collections.sort(list, transientListComparator);
					}
					closeLeastRecentlyAccessedTransientMap(processId, list);
					try{ Thread.sleep(IO_SLEEP_WAIT_MS); }catch(Throwable thrown){}
				}
			}
			retryCount++;
		}
	}
	
	private Comparator<Map.Entry<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>>> 
			transientListComparator 
			= 
			new Comparator<Map.Entry<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>>>(){
		@Override
		public int compare(
				Entry<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>> o1,
				Entry<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>> o2){
			if(o1 == null && o2 == null){
				return 0;
			}else if(o1 == null && o2 != null){
				return -1;
			}else if(o1 != null && o2 == null){
				return 1;
			}else{ // both non-null
				SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long> v1 = o1.getValue();
				SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long> v2 = o2.getValue();
				if(v1 == null && v2 == null){
					return 0;
				}else if(v1 == null && v2 != null){
					return -1;
				}else if(v1 != null && v2 == null){
					return 1;
				}else{ // both non-null
					Long l1 = v1.getValue();
					Long l2 = v2.getValue();
					if(l1 == null && l2 == null){
						return 0;
					}else if(l1 == null && l2 != null){
						return -1;
					}else if(l1 != null && l2 == null){
						return 1;
					}else{ // both non-null
						if(l1 < l2){
							return -1;
						}else if(l1 > l2){
							return 1;
						}else{
							return 0;
						}
					}
				}
			}
		}
	};
	
	/**
	 * The list of open maps is sorted ascending order on time i.e. the first one is the least recently used
	 * Keep reading the sorted list until a map found where the time is smallest, the value is non-null and value's group id is different than the one passed in argument
	 * If found then remove it from the sorted list in case we need to remove more later
	 * If a valid entry found then close (with flush = true), remove from open, add to close
	 * 
	 * @param currentProcessId
	 * @param sortedOpenList
	 */
	private void closeLeastRecentlyAccessedTransientMap(String currentProcessId,
			List<Map.Entry<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>>> sortedOpenList){
		int index = 0;
		Map.Entry<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>> entry = null;
		// Iterate over the sorted list until first (least recently used) map found or nothing in list left
		while(entry == null && index < sortedOpenList.size()){
			Map.Entry<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>> entryTmp = 
					sortedOpenList.get(index);
			if(entryTmp == null){
				index++;
				continue;
			}else{
				// If entry has the same id as currentProcessId then DON'T close that because we want that opened.
				if(entryTmp.getKey() != null && entryTmp.getKey().equals(currentProcessId)){
					index++;
					continue;
				}else{
					entry = entryTmp;
					sortedOpenList.remove(index);
					break;
				}
			}
		}
		
		if(entry == null){
			logger.log(Level.SEVERE, "Nothing closed because no valid entry found");
			// error
		}else{
			String processId = entry.getKey();
			if(processId != null){
				SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long> entrySimple = entry.getValue();
				if(entrySimple != null){
					ExternalMemoryMap<ArtifactIdentifier, ArtifactState> openMap = entrySimple.getKey();
					if(openMap != null){
						try{
							openMap.close(true);
							openTransientArtifactsMaps.remove(processId);
							closedTransientArtifactsMaps.put(processId, openMap);
						}catch(Throwable t){
							logger.log(Level.SEVERE, "Failed to close map with processId: " + processId, t);
						}
					}else{
						logger.log(Level.SEVERE, "Nothing closed because NULL map for processId: " + processId);
					}
				}else{
					logger.log(Level.SEVERE, "Nothing closed because NULL entry for processId: " + processId);
				}
			}else{
				logger.log(Level.SEVERE, "Nothing closed because NULL processId for entry: " + entry);
			}
		}
	}

	public void artifactCreated(ArtifactIdentifier identifier){
		boolean incrementEpoch = outputArtifact(identifier) && hasEpoch(identifier) 
				&& isEpochUpdatable(identifier);
		if(incrementEpoch){
			ExternalMemoryMap<ArtifactIdentifier, ArtifactState> artifactsMap = getResolvedArtifactMap(identifier);
			if(artifactsMap != null){
				boolean update = false;
				ArtifactState state = artifactsMap.get(identifier);
				if(state == null){
					state = new ArtifactState();
					artifactsMap.put(identifier, state);
					update = false;
				}else{
					update = true;
				}
				if(update){
					state.incrementEpoch();
				}
			}
		}
	}
	
	public void artifactVersioned(ArtifactIdentifier identifier){
		boolean incrementVersion = outputArtifact(identifier) && hasVersion(identifier) 
				&& isVersionUpdatable(identifier);
		if(incrementVersion){
			ExternalMemoryMap<ArtifactIdentifier, ArtifactState> artifactsMap = getResolvedArtifactMap(identifier); 
			if(artifactsMap != null){
				boolean update = false;
				ArtifactState state = artifactsMap.get(identifier);
				if(state == null){
					state = new ArtifactState();
					artifactsMap.put(identifier, state);
					update = false;
				}else{
					update = true;
				}
				if(update){
					state.incrementVersion();
				}
			}
		}
	}
	
	public void artifactPermissioned(ArtifactIdentifier identifier, String permissions){
		boolean updatePermissions = outputArtifact(identifier) && hasPermissions(identifier)
				&& isPermissionsUpdatable(identifier);
		if(updatePermissions){
			ExternalMemoryMap<ArtifactIdentifier, ArtifactState> artifactsMap = getResolvedArtifactMap(identifier); 
			if(artifactsMap != null){
				ArtifactState state = artifactsMap.get(identifier);
				if(state == null){
					state = new ArtifactState();
					artifactsMap.put(identifier, state);
				}
				state.updatePermissions(permissions);
			}
		}
	}
	
	public Artifact putArtifact(String time, String eventId, String operation, String pid, String source,
			ArtifactIdentifier identifier){
		BigInteger epoch = null, version = null;
		String permissions = null;
		if(outputArtifact(identifier)){
			ExternalMemoryMap<ArtifactIdentifier, ArtifactState> artifactsMap = getResolvedArtifactMap(identifier);
			if(artifactsMap != null){
				ArtifactState state = artifactsMap.get(identifier);
				if(state == null){
					state = new ArtifactState();
					artifactsMap.put(identifier, state);
				}
				
				boolean hasBeenPut = state.hasBeenPut();
				
				epoch = state.getEpoch();
				version = state.getVersion();
				permissions = state.getPermissions();
				
				Artifact artifact = getArtifact(identifier, epoch, version, permissions, source);
				
				if(!hasBeenPut){
					reporter.putVertex(artifact);
				}
				
				if(identifier instanceof FileIdentifier){
					ArtifactConfig config = artifactConfigs.get(identifier.getClass());
					
					BigInteger lastEpoch = state.getLastPutEpoch();
					BigInteger lastVersion = state.getLastPutVersion();
					String lastPermissions = state.getLastPutPermissions();
					
					// Special check
					if((config.hasVersion && lastVersion == null) || (config.hasEpoch && (lastEpoch == null || !CommonFunctions.bigIntegerEquals(lastEpoch, epoch)))){
						// First one so no derived edge
					}else{
						boolean permissionedUpdated = config.hasPermissions && config.canBePermissioned && !StringUtils.equals(lastPermissions, permissions);
						boolean versionUpdated = config.hasVersion && config.canBeVersioned && lastVersion != null && !CommonFunctions.bigIntegerEquals(lastVersion, version);
						if(versionUpdated || permissionedUpdated){
							Artifact lastArtifact = 
									getArtifact(identifier, lastEpoch, lastVersion, lastPermissions, source);
							WasDerivedFrom derivedEdge = new WasDerivedFrom(artifact, lastArtifact);
							derivedEdge.addAnnotation(OPMConstants.EDGE_PID, pid);
							reporter.putEdge(derivedEdge, operation, time, eventId, source);
						}
					}
				}
				
				// Always call put to keep the state in sync
				if(!hasBeenPut){
					state.put();
				}
				return artifact;
			}
		}
		return getArtifact(identifier, epoch, version, permissions, source);
	}
	
	private Artifact getArtifact(ArtifactIdentifier identifier, BigInteger epoch, BigInteger version,
			String permissions, String source){
		Artifact artifact = new Artifact();
		artifact.addAnnotations(getIdentifierAnnotations(identifier));
		artifact.addAnnotations(getStateAnnotations(identifier, epoch, version, permissions));
		addSourceAnnotation(artifact, source);
		return artifact;
	}
	
	private Map<String, String> getStateAnnotations(ArtifactIdentifier identifier, BigInteger epoch, 
			BigInteger version, String permissions){
		ArtifactConfig config = artifactConfigs.get(identifier.getClass());
		Map<String, String> annotations = new HashMap<String, String>();
		if(epoch != null && config.hasEpoch){
			annotations.put(OPMConstants.ARTIFACT_EPOCH, epoch.toString());
		}
		if(version != null && config.hasVersion){
			annotations.put(OPMConstants.ARTIFACT_VERSION, version.toString());
		}
		if(permissions != null && config.hasPermissions){
			annotations.put(OPMConstants.ARTIFACT_PERMISSIONS, permissions);
		}
		return annotations;
	}
	
	private Map<String, String> getIdentifierAnnotations(ArtifactIdentifier identifier){
		Map<String, String> annotations = identifier.getAnnotationsMap();
		annotations.put(OPMConstants.ARTIFACT_SUBTYPE, identifier.getSubtype());
		return annotations;
	}
	
	private void addSourceAnnotation(Map<String, String> annotations, String source){
		annotations.put(OPMConstants.SOURCE, source);
	}
	
	private void addSourceAnnotation(Artifact artifact, String source){
		addSourceAnnotation(artifact.getAnnotations(), source);;
	}
	
	public void doCleanUpForPid(String processId){
		String mapId = getTransientArtifactsMapId(processId);
		
		if(openTransientArtifactsMaps != null){
			SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long> entry = 
					openTransientArtifactsMaps.remove(processId);
			if(entry != null){
				ExternalMemoryMap<ArtifactIdentifier, ArtifactState> map = entry.getKey();
				if(map != null){
					CommonFunctions.closePrintSizeAndDeleteExternalMemoryMap(mapId, map);
				}
			}
		}
		
		if(closedTransientArtifactsMaps != null){
			ExternalMemoryMap<ArtifactIdentifier, ArtifactState> map = closedTransientArtifactsMaps.remove(processId);
			if(map != null){
				CommonFunctions.closePrintSizeAndDeleteExternalMemoryMap(mapId, map);
			}
		}
	}
	
	public void doCleanUp(){
		if(persistentArtifactsMap != null){
			CommonFunctions.closePrintSizeAndDeleteExternalMemoryMap(persistentArtifactsMapId, persistentArtifactsMap);
			persistentArtifactsMap = null;
		}
		if(openTransientArtifactsMaps != null){
			for(Map.Entry<String, SimpleEntry<ExternalMemoryMap<ArtifactIdentifier, ArtifactState>, Long>> entry : 
					openTransientArtifactsMaps.entrySet()){
				if(entry != null){
					String processId = entry.getKey();
					String transientMapId = getTransientArtifactsMapId(processId);
					ExternalMemoryMap<ArtifactIdentifier, ArtifactState> transientMap = entry.getValue().getKey();
					CommonFunctions.closePrintSizeAndDeleteExternalMemoryMap(transientMapId, transientMap);
				}
			}
			openTransientArtifactsMaps.clear();
		}
		if(closedTransientArtifactsMaps != null){
			for(Map.Entry<String, ExternalMemoryMap<ArtifactIdentifier, ArtifactState>> entry : 
				closedTransientArtifactsMaps.entrySet()){
				if(entry != null){
					String processId = entry.getKey();
					String transientMapId = getTransientArtifactsMapId(processId);
					ExternalMemoryMap<ArtifactIdentifier, ArtifactState> transientMap = entry.getValue();
					CommonFunctions.closePrintSizeAndDeleteExternalMemoryMap(transientMapId, transientMap);
				}
			}
			closedTransientArtifactsMaps.clear();
		}
	}
}