/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ace.client.xworkspace;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.ace.client.repository.Association;
import org.apache.ace.client.repository.ObjectRepository;
import org.apache.ace.client.repository.RepositoryObject;
import org.apache.ace.client.repository.helper.ArtifactHelper;
import org.apache.ace.client.repository.object.Artifact2FeatureAssociation;
import org.apache.ace.client.repository.object.ArtifactObject;
import org.apache.ace.client.repository.object.Distribution2TargetAssociation;
import org.apache.ace.client.repository.object.DistributionObject;
import org.apache.ace.client.repository.object.Feature2DistributionAssociation;
import org.apache.ace.client.repository.object.FeatureObject;
import org.apache.ace.client.repository.stateful.StatefulTargetObject;
import org.osgi.resource.Resource;
import org.osgi.service.useradmin.User;

/**
 * Workspace represents the modifiable client-side state of an ACE repository. It facilitates a workflow whereby a
 * repository can be checked out, queried, modified and committed back to the server.
 * <p>
 * Workspace has a generic API based on RepositoryObjects and their associations, as well as a more specific one dealing
 * with resource processors, artifacts, features, distributions and targets. The latter is mostly intended for
 * scripting, hence the shorthand notation of its method names:
 * <p>
 * Command syntax, first character is the "operation", then the "entity type" or "association". Note: not all
 * combinations exist.<br>
 * Operations: [c]reate, [l]ist, [d]elete, [u]pdate<br>
 * Entities: [a]rtifact, [f]eature, [d]istribution, [t]arget<br>
 * Associations: [a2f], [f2d], [d2t]<br>
 * <p>
 * Workspace objects are most commonly obtained from a WorkspaceManager acting on behalf of the client.
 * 
 * @see ObjectRepository
 * @see WorkspaceManager
 */
public interface Workspace extends org.apache.ace.client.workspace.Workspace {
    /*** export/import 
     * @throws Exception ***/
	public void expw(String directoryPath) throws Exception;
	
	public void expw(String directoryPath, String target)  throws Exception;
	/***
	 * @param directoryPath
	 * @param exportFile
	 * @throws Exception
	 */
	public List<String> getTargetExportFilePaths(String directoryPath);
	
	public void impw(String directoryPath, String exportFile)  throws Exception;
	
	public void impw(String directoryPath)  throws Exception;
	
	public void cpytgs(RepositoryObject src, RepositoryObject tgt) throws Exception;
}
