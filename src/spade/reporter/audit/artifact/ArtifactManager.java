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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
			
			CONFIG_KEY_MAX_OPEN_RETRY_COUNT = "maxopenretries",
			CONFIG_KEY_TRANSIENT_MAPS_MAP_REPORTING_INTERVAL_SECONDS = "transientmapsmapreportinginterval",
			CONFIG_KEY_TRANSIENT_MAPS_FAILED_OPEN_CLOSE_PERCENTAGE = "closepercentageonfailedopen";
	
	private static final String[] mandatoryConfigKeys = {CONFIG_KEY_PARENT_DIR, //CONFIG_KEY_PERSISTENT_SUB_DIR, 
			CONFIG_KEY_PERSISTENT_DB_NAME, CONFIG_KEY_PERSISTENT_CACHE_SIZE, CONFIG_KEY_PERSISTENT_BF_FP_PROB,
			CONFIG_KEY_PERSISTENT_BF_EXPECTED_ELEMENTS, CONFIG_KEY_PERSISTENT_BF_EXPECTED_ELEMENTS,
			CONFIG_KEY_PERSISTENT_REPORTING_INTERVAL_SECONDS, CONFIG_KEY_PERSISTENT_STORE_CLASS_NAME,
			//CONFIG_KEY_TRANSIENT_SUB_DIR_PREFIX, 
			CONFIG_KEY_TRANSIENT_DB_NAME_PREFIX, CONFIG_KEY_TRANSIENT_CACHE_SIZE, CONFIG_KEY_TRANSIENT_BF_FP_PROB,
			CONFIG_KEY_TRANSIENT_BF_EXPECTED_ELEMENTS, CONFIG_KEY_TRANSIENT_REPORTING_INTERVAL_SECONDS,
			CONFIG_KEY_TRANSIENT_STORE_CLASS_NAME, CONFIG_KEY_MAX_OPEN_RETRY_COUNT,
			CONFIG_KEY_TRANSIENT_MAPS_FAILED_OPEN_CLOSE_PERCENTAGE};
	
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
	private double closePercentageOnFailedOpen = 0;
	private long configTransientMapsMapReportingIntervalMillis;
	private long lastTransientMapsMapReportedMillis = 0;
	
	private final long IO_SLEEP_WAIT_MS = 50;
	
	private boolean reportingTransientMapsStats = false;
	private Stats globalStats = null, intervalStats = null;
	
//	private BigInteger sumUniqueAccessCounts = BigInteger.ZERO;
//	private BigInteger intervalCount = BigInteger.ZERO;
	
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
	
	private Map<String, TransientArtifactMapContainer> groupIdToMapContainer = new HashMap<String, TransientArtifactMapContainer>();
	
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
		
		String transientMapsMapReportingIntervalSecondsString = 
				configMap.get(CONFIG_KEY_TRANSIENT_MAPS_MAP_REPORTING_INTERVAL_SECONDS);
		if(transientMapsMapReportingIntervalSecondsString != null){
			Integer seconds = CommonFunctions.parseInt(transientMapsMapReportingIntervalSecondsString, null);
			if(seconds == null){
				throw new Exception("Value for key '"+CONFIG_KEY_TRANSIENT_MAPS_MAP_REPORTING_INTERVAL_SECONDS+
						"' must be integer in default config file");
			}else{
				if(seconds < 0){
					throw new Exception("Value for key '"+CONFIG_KEY_TRANSIENT_MAPS_MAP_REPORTING_INTERVAL_SECONDS+
							"' must be a non-negative integer in default config file");
				}else{
					configTransientMapsMapReportingIntervalMillis = seconds * 1000;
					reportingTransientMapsStats = true;
					globalStats = new Stats();
				}
			}
		}
		
		String closePercentageOnFailedOpenValue = configMap.get(CONFIG_KEY_TRANSIENT_MAPS_FAILED_OPEN_CLOSE_PERCENTAGE);
		if(closePercentageOnFailedOpenValue == null){
			throw new Exception("NULL value for key '"+CONFIG_KEY_TRANSIENT_MAPS_FAILED_OPEN_CLOSE_PERCENTAGE+"' in default config file");
		}else{
			Double closePercentageOnFailedOpenDouble = CommonFunctions.parseDouble(closePercentageOnFailedOpenValue, null);
			if(closePercentageOnFailedOpenDouble == null){
				throw new Exception("Only floating point values allowed for key '"+CONFIG_KEY_TRANSIENT_MAPS_FAILED_OPEN_CLOSE_PERCENTAGE+"' in default config file");
			}else{
				if(closePercentageOnFailedOpenDouble < 0 || closePercentageOnFailedOpenDouble > 1){
					throw new Exception("Only [0-1] range value for key '"+CONFIG_KEY_TRANSIENT_MAPS_FAILED_OPEN_CLOSE_PERCENTAGE+"' in default config file");
				}else{
					closePercentageOnFailedOpen = closePercentageOnFailedOpenDouble;
				}
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
	
	private void printTransientStats(){
		if(reportingTransientMapsStats){
			if(System.currentTimeMillis() - lastTransientMapsMapReportedMillis > configTransientMapsMapReportingIntervalMillis){
//				intervalCount = intervalCount.add(BigInteger.ONE);
//				sumUniqueAccessCounts = sumUniqueAccessCounts.add(
//						new BigInteger(String.valueOf(globalStats.accessedGroupTransientMaps.size())));
				
				Stats diffStats = null;
				if(intervalStats == null){
					// First interval
					diffStats = globalStats;
				}else{
					diffStats = Stats.diff(globalStats, intervalStats);
				}
				intervalStats = globalStats.copy();
				logger.log(Level.INFO, "(INTERVAL) Transient maps stats [ {0} ]", 
						new Object[]{
								diffStats.toString(), groupIdToMapContainer.size()
						});
				logger.log(Level.INFO, "(GLOBAL) Transient maps stats [ {0} ], TotalMaps={1}", 
						new Object[]{
								globalStats.toString(), groupIdToMapContainer.size()
						});
				lastTransientMapsMapReportedMillis = System.currentTimeMillis();
				globalStats.accessedGroupTransientMaps.clear(); // Clear because only for interval. High memory overhead if global.
			}
		}
	}
	
	/**
	 * If identifier is subclass of TransientArtifactIdentifer then:
	 * 		
	 * 		1) If map for groupid and grouptime exists which is also open then return that.
	 * 		2) If map for groupid and grouptime exists which is closed then try opening it and return that.
	 * 		3) If map for groupid does NOT exist then try to create it and return that.
	 * 		4) If map for groupid exists but grouptime is different then delete the existing map and create a new one.
	 * 			a) Need to do this:
	 * 				i) if missed exit for group id and then missed the creation for that group id too OR
	 * 				ii) if process killed or any died without any monitored syscall
	 * 		
	 * 		Always mark the accessed time!
	 * 		
	 * else:
	 * 		return the persistent artifacts map
	 * 
	 * @param identifier artifact identifier
	 * @return
	 */
	private ExternalMemoryMap<ArtifactIdentifier, ArtifactState> getResolvedArtifactMap(ArtifactIdentifier identifier){
		printTransientStats();
		if(identifier instanceof TransientArtifactIdentifier){
			TransientArtifactIdentifier transientIdentifier = (TransientArtifactIdentifier)(identifier);
			String processId = transientIdentifier.getGroupId();
			String processTime = transientIdentifier.getGroupTime();
			
			if(reportingTransientMapsStats){
				globalStats.accessedGroupTransientMaps.add(processId);
				globalStats.incrementAccessedTransientMaps();
			}
			
			TransientArtifactMapContainer container = groupIdToMapContainer.get(processId);
			
			// Checking if there exists container with the same pid but different ptime
			// Means that the process had died and a new with a same pid is running now
			if(container != null){
				if(!StringUtils.equals(container.groupTime, processTime)){
					container.deleteMap();
					if(reportingTransientMapsStats){
						globalStats.incrementIndirectlyDeletedTransientMaps();
					}
					groupIdToMapContainer.remove(processId);
					container = null; // Set it to null so that it can be initialized below
				}
			}
			
			if(container == null){
				container = new TransientArtifactMapContainer(processId, processTime);
				groupIdToMapContainer.put(processId, container);
			}
			
			container.accessed();
			
			openTransientMap(container);
			
			if(container.map == null || container.map.isExternalStoreClosed()){
				logger.log(Level.WARNING, "Failed to open external store for processId: " + processId + 
						". Using persisted map. Garbage collection will fail for this process.");
				return persistentArtifactsMap;
			}else{
				return container.map;
			}
		}else{
			return persistentArtifactsMap;
		}
	}
	
	/**
	 * While retry counts have not been exhausted and while the required map has not been created/opened then
	 * keep doing the following:
	 * 		
	 * 		1) Create a list of non-null, open, and of different groupId than the passed container
	 * 		2) Sort the list with decreasing access time
	 * 		3) Find the number of opened maps to close based on the value in config file. Close and remove all those.
	 * 
	 * @param container
	 */
	private void openTransientMap(TransientArtifactMapContainer container){
		int retryCount = 0;
		
		boolean listSorted = false;
		final List<TransientArtifactMapContainer> sortedOpenList = new ArrayList<TransientArtifactMapContainer>();
		
		while(container.map == null || container.map.isExternalStoreClosed()){
			try{
				container.createOrOpenMap();
				// If failed without exception
				if(container.map == null || container.map.isExternalStoreClosed()){
					throw new Exception("Silently failed to open/init external store for processId: " + container.groupId);
				}
			}catch(Throwable t){
				// org.fusesource.leveldbjni.internal.NativeDB$DBException
				// com.sleepycat.je.EnvironmentFailureException
				// Failed to open
				if(reportingTransientMapsStats){
					globalStats.incrementOpenRetriesTransientMaps();
					BigInteger transientMapOpenExceptionClassCount = null;
					if((transientMapOpenExceptionClassCount = globalStats.transientMapOpenExceptionClassToCount.get(t.getClass())) == null){
						transientMapOpenExceptionClassCount = BigInteger.ZERO;
					}else{
						transientMapOpenExceptionClassCount = transientMapOpenExceptionClassCount.add(BigInteger.ONE);
					}
					globalStats.transientMapOpenExceptionClassToCount.put(t.getClass(), transientMapOpenExceptionClassCount);
				}
				
				if(retryCount > maxRetryCount){
					logger.log(Level.SEVERE, 
							retryCount + " out of " + maxRetryCount + " retries exhausted to open transient artifacts map for "
									+ "processId: " + container.groupId, t);
					break;
				}else{
					// retry. continue.
					// close the least recently accessed on
					if(!listSorted){
						groupIdToMapContainer.forEach((k,v) -> {
							// Only add those containers which don't belong to this pid, non-null, and open
							if(!StringUtils.equals(k, container.groupId) 
									&& v != null && v.map != null && !v.map.isExternalStoreClosed()){
								sortedOpenList.add(v);
							}
						});
						Collections.sort(sortedOpenList, transientListComparatorDescending);
						listSorted = true;
					}
					int closeMapsCount = (int)Math.ceil((closePercentageOnFailedOpen * (double)(sortedOpenList.size()))); 
					// Ceil because always try to remove & close at least one if possible.
					for(int a = 0; a < closeMapsCount && sortedOpenList.size() > 0; a++){
						TransientArtifactMapContainer leastRecentlyAccessed = sortedOpenList.remove(sortedOpenList.size() - 1);
						try{
							leastRecentlyAccessed.closeForReopenMap();
						}catch(Throwable tOnClose){
							logger.log(Level.SEVERE, "Failed to close map with processId: " + leastRecentlyAccessed.groupId, tOnClose);
						}
					}
					try{ Thread.sleep(IO_SLEEP_WAIT_MS); }catch(Throwable thrown){}
				}
			}
			retryCount++;
		}
	}

	private Comparator<TransientArtifactMapContainer> transientListComparatorDescending = 
			new Comparator<TransientArtifactMapContainer>(){
		@Override
		public int compare(TransientArtifactMapContainer o1, TransientArtifactMapContainer o2){
			if(o1 == null && o2 == null){
				return 0;
			}else if(o1 == null && o2 != null){
				return -1;
			}else if(o1 != null && o2 == null){
				return 1;
			}else{ // both non-null
				long l1 = o1.lastAccessedTime;
				long l2 = o2.lastAccessedTime;
				if(l1 < l2){
					return 1;
				}else if(l1 > l2){
					return -1;
				}else{
					return 0;
				}
			}
		}
	};

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
		if(groupIdToMapContainer != null){
			TransientArtifactMapContainer container = groupIdToMapContainer.remove(processId);
			if(container != null){
				container.deleteMap();
				if(reportingTransientMapsStats){
					globalStats.incrementDirectlyDeletedTransientMaps();
				}
			}
		}
	}
	
	public void doCleanUp(){
		if(persistentArtifactsMap != null){
			CommonFunctions.closePrintSizeAndDeleteExternalMemoryMap(persistentArtifactsMapId, persistentArtifactsMap);
			persistentArtifactsMap = null;
		}
		if(groupIdToMapContainer != null){
			for(TransientArtifactMapContainer container : groupIdToMapContainer.values()){
				if(container != null){
					container.deleteMap();
				}
			}
			groupIdToMapContainer.clear();
		}
	}
	
	/**
	 * A container for storing the state of external memory maps of currently active pids
	 * 
	 * TODO remove an entry if closed and inactive for 'x' amount of time. Need to save bloomfilter 
	 * because it is needed when inflating the external memory map.
	 */
	private class TransientArtifactMapContainer{
		/**
		 * Pid, memory tgid, fd tgid, and etc
		 */
		final String groupId;
		/**
		 * Start or seen time stored for the above referenced groupId
		 */
		final String groupTime;
		/**
		 * Time when the above referenced groupId was accessed
		 * Used for deciding which map to close. 
		 * System.nanoTime() at the moment.
		 */
		long lastAccessedTime = 0;
		/**
		 * The MAP
		 */
		ExternalMemoryMap<ArtifactIdentifier, ArtifactState> map = null;
		private TransientArtifactMapContainer(String groupId, String groupTime){
			this.groupId = groupId;
			this.groupTime = groupTime;
		}
		private void accessed(){
			lastAccessedTime = System.nanoTime();
		}
		private void createOrOpenMap() throws Throwable{
			if(map == null){
				map = initTransientArtifactsMap(groupId);
				if(reportingTransientMapsStats){
					globalStats.incrementCreatedTransientMaps();
				}
			}else{
				if(map.isExternalStoreClosed()){
					map.reopenExternalStore();
					if(reportingTransientMapsStats){
						globalStats.incrementReopenedTransientMaps();
					}
				}
			}
		}
		private void closeForReopenMap() throws Throwable{
			if(map != null && !map.isExternalStoreClosed()){
				map.close(true);
				if(reportingTransientMapsStats){
					globalStats.incrementClosedTransientMaps();
				}
			}
		}
		private void deleteMap(){
			if(map != null){
				String mapId = getTransientArtifactsMapId(groupId);
				CommonFunctions.closePrintSizeAndDeleteExternalMemoryMap(mapId, map);
			}
		}
	}
	
	/**
	 * A class to keep track of data related to Transient Maps
	 */
	private static class Stats{
		/**
		 * Count of reopen calls on transient maps
		 */
		private BigInteger reopenedTransientMaps = BigInteger.ZERO;
		/**
		 * Count of close calls on transient maps
		 */
		private BigInteger closedTransientMaps = BigInteger.ZERO;
		/**
		 * Count of new transient maps creations
		 */
		private BigInteger createdTransientMaps = BigInteger.ZERO;
		/**
		 * Count of explicitly deleted transient maps
		 */
		private BigInteger directlyDeletedTransientMaps = BigInteger.ZERO;
		/**
		 * Count of indirectly deleted transient maps. i.e. process with pid p1 seen at t1 with process time pT1, 
		 * and then process with pid p1 seen at t2 with process time pT2 then existing data deleted for pid p1.
		 */
		private BigInteger indirectlyDeletedTransientMaps = BigInteger.ZERO;
		/**
		 * Count of times open/creation of transient maps were tried unsuccessfully
		 */
		private BigInteger openRetriesTransientMaps = BigInteger.ZERO;
		/**
		 * Total number of accesses to transient maps
		 */
		private BigInteger accessedTransientMaps = BigInteger.ZERO;
		/**
		 * Exception class to  number of times that exception occurred with trying to open/create a transient map
		 */
		private Map<Class<?>, BigInteger> transientMapOpenExceptionClassToCount = new HashMap<Class<?>, BigInteger>();
		/**
		 * Not to be kept globally - CLEARED AT EACH INTERVAL
		 * Pids of processes which were referred to
		 */
		private Set<String> accessedGroupTransientMaps = new HashSet<String>(); // For unique pid accesses
		/**
		 * size of 'accessedGroupTransientMaps'
		 */
		private long uniqueGroupsAccessed = 0;
		
		private void incrementReopenedTransientMaps(){ reopenedTransientMaps = reopenedTransientMaps.add(BigInteger.ONE); }
		private void incrementClosedTransientMaps(){ closedTransientMaps = closedTransientMaps.add(BigInteger.ONE); }
		private void incrementCreatedTransientMaps(){ createdTransientMaps = createdTransientMaps.add(BigInteger.ONE); }
		private void incrementDirectlyDeletedTransientMaps(){ directlyDeletedTransientMaps = directlyDeletedTransientMaps.add(BigInteger.ONE); }
		private void incrementIndirectlyDeletedTransientMaps(){ indirectlyDeletedTransientMaps = indirectlyDeletedTransientMaps.add(BigInteger.ONE); }
		private void incrementOpenRetriesTransientMaps(){ openRetriesTransientMaps = openRetriesTransientMaps.add(BigInteger.ONE); }
		private void incrementAccessedTransientMaps(){ accessedTransientMaps = accessedTransientMaps.add(BigInteger.ONE); }
		
		public String toString(){
			return String.format("Reopened=%s, Closed=%s, Created=%s, DirectlyDeleted=%s, IndirectlyDeleted=%s, "
					+ "OpenRetries=%s, OpenFailExceptionCounts=%s, AccessedOverall=%s, AccessedUnique=%s", 
					reopenedTransientMaps, closedTransientMaps, createdTransientMaps,
					directlyDeletedTransientMaps, indirectlyDeletedTransientMaps, openRetriesTransientMaps,
					transientMapOpenExceptionClassToCount, accessedTransientMaps, uniqueGroupsAccessed);
		}
		/**
		 * @return an exact copy except the 'accessedGroupTransientMaps'
		 */
		private Stats copy(){
			Stats copy = new Stats();
			copy.reopenedTransientMaps = reopenedTransientMaps;
			copy.closedTransientMaps = closedTransientMaps;
			copy.createdTransientMaps = createdTransientMaps;
			copy.directlyDeletedTransientMaps = directlyDeletedTransientMaps;
			copy.indirectlyDeletedTransientMaps = indirectlyDeletedTransientMaps;
			copy.openRetriesTransientMaps = openRetriesTransientMaps;
			copy.accessedTransientMaps = accessedTransientMaps;
			copy.transientMapOpenExceptionClassToCount = new HashMap<Class<?>, BigInteger>(transientMapOpenExceptionClassToCount);
			return copy;
		}
		private static Stats diff(Stats minuend, Stats subtrahend){
			Stats diff = new Stats();
			diff.reopenedTransientMaps = minuend.reopenedTransientMaps.subtract(subtrahend.reopenedTransientMaps);
			diff.closedTransientMaps = minuend.closedTransientMaps.subtract(subtrahend.closedTransientMaps);
			diff.createdTransientMaps = minuend.createdTransientMaps.subtract(subtrahend.createdTransientMaps);
			diff.directlyDeletedTransientMaps = minuend.directlyDeletedTransientMaps.subtract(subtrahend.directlyDeletedTransientMaps);
			diff.indirectlyDeletedTransientMaps = minuend.indirectlyDeletedTransientMaps.subtract(subtrahend.indirectlyDeletedTransientMaps);
			diff.openRetriesTransientMaps = minuend.openRetriesTransientMaps.subtract(subtrahend.openRetriesTransientMaps);
			diff.accessedTransientMaps = minuend.accessedTransientMaps.subtract(subtrahend.accessedTransientMaps);
			for(Class<?> clazz : minuend.transientMapOpenExceptionClassToCount.keySet()){
				BigInteger v2 = minuend.transientMapOpenExceptionClassToCount.get(clazz);
				BigInteger v1 = subtrahend.transientMapOpenExceptionClassToCount.get(clazz);
				if(v2 == null){ v2 = BigInteger.ZERO; }
				if(v1 == null){ v1 = BigInteger.ZERO; }
				BigInteger diffVal = v2.subtract(v1);
				diff.transientMapOpenExceptionClassToCount.put(clazz, diffVal);
			}
			diff.uniqueGroupsAccessed = minuend.accessedGroupTransientMaps.size();
			return diff;
		}
	}
}