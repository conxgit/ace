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
package org.apache.ace.client.xworkspace.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.jar.Attributes;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.ace.client.repository.Association;
import org.apache.ace.client.repository.ObjectRepository;
import org.apache.ace.client.repository.RepositoryAdmin;
import org.apache.ace.client.repository.RepositoryAdminLoginContext;
import org.apache.ace.client.repository.RepositoryObject;
import org.apache.ace.client.repository.SessionFactory;
import org.apache.ace.client.repository.helper.bundle.BundleHelper;
import org.apache.ace.client.repository.object.Artifact2FeatureAssociation;
import org.apache.ace.client.repository.object.ArtifactObject;
import org.apache.ace.client.repository.object.Distribution2TargetAssociation;
import org.apache.ace.client.repository.object.DistributionObject;
import org.apache.ace.client.repository.object.Feature2DistributionAssociation;
import org.apache.ace.client.repository.object.FeatureObject;
import org.apache.ace.client.repository.repository.Artifact2FeatureAssociationRepository;
import org.apache.ace.client.repository.repository.ArtifactRepository;
import org.apache.ace.client.repository.repository.Distribution2TargetAssociationRepository;
import org.apache.ace.client.repository.repository.DistributionRepository;
import org.apache.ace.client.repository.repository.Feature2DistributionAssociationRepository;
import org.apache.ace.client.repository.repository.FeatureRepository;
import org.apache.ace.client.repository.stateful.StatefulTargetObject;
import org.apache.ace.client.repository.stateful.StatefulTargetRepository;
import org.apache.ace.client.repository.stateful.StatefulTargetObject.ApprovalState;
import org.apache.ace.client.xworkspace.Workspace;
import org.apache.felix.dm.Component;
import org.apache.felix.dm.DependencyManager;
import org.apache.xerces.util.DOMUtil;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Filter;
import org.osgi.framework.Version;
import org.osgi.resource.Capability;
import org.osgi.resource.Resource;
import org.osgi.service.log.LogService;
import org.osgi.service.useradmin.User;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class WorkspaceImpl implements Workspace {

    private final String m_sessionID;
    private final URL m_repositoryURL;
    private final String m_storeCustomerName;
    private final String m_distributionCustomerName;
    private final String m_deploymentCustomerName;
    private final String m_storeRepositoryName;
    private final String m_distributionRepositoryName;
    private final String m_deploymentRepositoryName;

    private volatile BundleContext m_context;
    private volatile DependencyManager m_manager;
    private volatile RepositoryAdmin m_repositoryAdmin;
    private volatile ArtifactRepository m_artifactRepository;
    private volatile FeatureRepository m_featureRepository;
    private volatile DistributionRepository m_distributionRepository;
    private volatile StatefulTargetRepository m_statefulTargetRepository;
    private volatile Artifact2FeatureAssociationRepository m_artifact2FeatureAssociationRepository;
    private volatile Feature2DistributionAssociationRepository m_feature2DistributionAssociationRepository;
    private volatile Distribution2TargetAssociationRepository m_distribution2TargetAssociationRepository;
    private volatile LogService m_log;

    public WorkspaceImpl(String sessionID, String repositoryURL, String customerName, String storeRepositoryName,
        String distributionRepositoryName, String deploymentRepositoryName) throws MalformedURLException {
        this(sessionID, repositoryURL, customerName, storeRepositoryName, customerName, distributionRepositoryName,
            customerName, deploymentRepositoryName);
    }

    public WorkspaceImpl(String sessionID, String repositoryURL, String storeCustomerName, String storeRepositoryName,
        String distributionCustomerName, String distributionRepositoryName, String deploymentCustomerName,
        String deploymentRepositoryName) throws MalformedURLException {
        m_sessionID = sessionID;
        m_repositoryURL = new URL(repositoryURL);
        m_storeCustomerName = storeCustomerName;
        m_distributionCustomerName = deploymentCustomerName;
        m_deploymentCustomerName = deploymentCustomerName;
        m_storeRepositoryName = storeRepositoryName;
        m_distributionRepositoryName = distributionRepositoryName;
        m_deploymentRepositoryName = deploymentRepositoryName;
    }

    @Override
    public String getSessionID() {
        return m_sessionID;
    }

    private void addSessionDependency(Component component, Class<?> service, boolean isRequired) {
        component.add(m_manager.createServiceDependency()
            .setService(service, "(" + SessionFactory.SERVICE_SID + "=" + m_sessionID + ")")
            .setRequired(isRequired));
    }

    private void addDependency(Component component, Class<?> service, boolean isRequired) {
        component.add(m_manager.createServiceDependency().setService(service).setRequired(isRequired));
    }

    public void init(Component component) {
        addSessionDependency(component, RepositoryAdmin.class, true);
        addSessionDependency(component, ArtifactRepository.class, true);
        addSessionDependency(component, FeatureRepository.class, true);
        addSessionDependency(component, DistributionRepository.class, true);
        addSessionDependency(component, StatefulTargetRepository.class, true);
        addSessionDependency(component, Artifact2FeatureAssociationRepository.class, true);
        addSessionDependency(component, Feature2DistributionAssociationRepository.class, true);
        addSessionDependency(component, Distribution2TargetAssociationRepository.class, true);
        addDependency(component, LogService.class, false);
    }

    public void start() {
    }

    public void destroy() {
    }

    @Override
    public boolean login(User user) {
        try {
            RepositoryAdminLoginContext context = m_repositoryAdmin.createLoginContext(user);

            context.add(
                context.createShopRepositoryContext().setLocation(m_repositoryURL).setCustomer(m_storeCustomerName)
                    .setName(m_storeRepositoryName).setWriteable())
                .add(context.createTargetRepositoryContext().setLocation(m_repositoryURL)
                    .setCustomer(m_distributionCustomerName).setName(m_distributionRepositoryName)
                    .setWriteable())
                .add(context.createDeploymentRepositoryContext().setLocation(m_repositoryURL)
                    .setCustomer(m_deploymentCustomerName).setName(m_deploymentRepositoryName).setWriteable());

            m_repositoryAdmin.login(context);
            m_repositoryAdmin.checkout();
        }
        catch (IOException e) {
            e.printStackTrace();
            m_log.log(LogService.LOG_ERROR,
                "Could not login and checkout. Workspace will probably not work correctly.", e);
            return false;
        }

        return true;
    }

    @Override
    public void checkout() throws IOException {
        m_repositoryAdmin.checkout();
    }

    @Override
    public void commit() throws IOException {
        m_repositoryAdmin.commit();
    }

    @Override
    public void logout() throws IOException {
        try {
            m_repositoryAdmin.logout(true);
            m_repositoryAdmin.deleteLocal();
        }
        catch (IllegalStateException ise) {
            m_log.log(LogService.LOG_DEBUG, "Nobody was logged into this session, continuing.");
        }
    }

    @Override
    public RepositoryObject getRepositoryObject(String entityType, String entityId) {
        ObjectRepository<?> repo = getGenericObjectRepository(entityType);
        return repo.get(entityId);
    }

    @Override
    public List<RepositoryObject> getRepositoryObjects(String entityType) {
        return getGenericRepositoryObjects(entityType);
    }

    @Override
    public RepositoryObject createRepositoryObject(String entityType, Map<String, String> attributes,
        Map<String, String> tags) throws IllegalArgumentException {
        if (TARGET.equals(entityType)) {
            ObjectRepository<StatefulTargetObject> repo = getGenericObjectRepository(TARGET);
            StatefulTargetRepository statefulRepo = (StatefulTargetRepository) repo;
            return statefulRepo.preregister(attributes, tags);
        }
        else {
            prepareAssociationAttributes(entityType, attributes);
            ObjectRepository<?> repo = getGenericObjectRepository(entityType);
            return repo.create(attributes, tags);
        }
    }

    // Note: this method looks very similar to updateAssociationAttributes. However, they are subtly different and can't
    // be integrated given the current API.
    private void prepareAssociationAttributes(String entityType, Map<String, String> attributes) {
        if (ARTIFACT2FEATURE.equals(entityType) || FEATURE2DISTRIBUTION.equals(entityType)
            || DISTRIBUTION2TARGET.equals(entityType)) {

            String leftAttribute = attributes.get("left");
            String rightAttribute = attributes.get("right");

            RepositoryObject left = null;
            if (leftAttribute != null) {
                left = getLeft(entityType, leftAttribute);
            }

            RepositoryObject right = null;
            if (rightAttribute != null) {
                right = getRight(entityType, rightAttribute);
            }

            if (left != null) {
                if (left instanceof StatefulTargetObject) {
                    if (((StatefulTargetObject) left).isRegistered()) {
                        attributes.put(Association.LEFT_ENDPOINT, ((StatefulTargetObject) left).getTargetObject()
                            .getAssociationFilter(attributes));
                    }
                }
                else {
                    attributes.put(Association.LEFT_ENDPOINT, left.getAssociationFilter(attributes));
                }
            } 
            if (right != null) {
                if (right instanceof StatefulTargetObject) {
                    if (((StatefulTargetObject) right).isRegistered()) {
                        attributes.put(Association.RIGHT_ENDPOINT, ((StatefulTargetObject) right).getTargetObject()
                            .getAssociationFilter(attributes));
                    }
                }
                else {
                    attributes.put(Association.RIGHT_ENDPOINT, right.getAssociationFilter(attributes));
                }
            }

            // ACE-523 Allow the same semantics as with createAssocation, ca2f, cf2d & cd2t...
            leftAttribute = attributes.get(Association.LEFT_CARDINALITY);
            rightAttribute = attributes.get(Association.RIGHT_CARDINALITY);

            if (leftAttribute != null) {
                attributes.put(Association.LEFT_CARDINALITY, interpretCardinality(leftAttribute));
            }
            if (rightAttribute != null) {
                attributes.put(Association.RIGHT_CARDINALITY, interpretCardinality(rightAttribute));
            }
        }
    }

    @Override
    public void updateRepositoryObject(String entityType, String entityId, Map<String, String> attributes,
        Map<String, String> tags) {
        RepositoryObject repositoryObject = getRepositoryObject(entityType, entityId);
        // first handle the attributes
        for (Entry<String, String> attribute : attributes.entrySet()) {
            String key = attribute.getKey();
            String value = attribute.getValue();
            // only add/update the attribute if it actually changed
            if (!value.equals(repositoryObject.getAttribute(key))) {
                repositoryObject.addAttribute(key, value);
            }
        }
        Enumeration<String> keys = repositoryObject.getAttributeKeys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            if (!attributes.containsKey(key)) {
                repositoryObject.removeAttribute(key);
            }
        }
        updateAssociationAttributes(entityType, repositoryObject);
        updateTags(tags, repositoryObject);
    }

    @Override
    public void idp(String dpURL) throws Exception {
        idp(dpURL, true /* autoCommit */);
    }

    @Override
    public void idp(String dpURL, boolean autoCommit) throws Exception {
        // Delegate all complexity to a separate helper class...
        new DPHelper(this, m_log).importDeploymentPackage(dpURL, autoCommit);
    }

    private void updateTags(Map<String, String> tags, RepositoryObject repositoryObject) {
        Enumeration<String> keys;
        // now handle the tags in a similar way
        for (Entry<String, String> attribute : tags.entrySet()) {
            String key = attribute.getKey();
            String value = attribute.getValue();
            // only add/update the tag if it actually changed
            if (!value.equals(repositoryObject.getTag(key))) {
                repositoryObject.addTag(key, value);
            }
        }
        keys = repositoryObject.getTagKeys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            if (!tags.containsKey(key)) {
                repositoryObject.removeTag(key);
            }
        }
    }

    // Note: this method looks very similar to prepareAssociationAttributes. However, they are subtly different and
    // can't be integrated given the current API.
    private void updateAssociationAttributes(String entityType, RepositoryObject repositoryObject) {
        if (ARTIFACT2FEATURE.equals(entityType) || FEATURE2DISTRIBUTION.equals(entityType)
            || DISTRIBUTION2TARGET.equals(entityType)) {
            String leftAttribute = repositoryObject.getAttribute("left");
            String rightAttribute = repositoryObject.getAttribute("right");

            RepositoryObject left = null;
            if (leftAttribute != null) {
                left = getLeft(entityType, leftAttribute);
            }

            RepositoryObject right = null;
            if (rightAttribute != null) {
                right = getRight(entityType, rightAttribute);
            }

            if (left != null) {
                if (left instanceof StatefulTargetObject) {
                    if (((StatefulTargetObject) left).isRegistered()) {
                        repositoryObject.addAttribute(
                            Association.LEFT_ENDPOINT,
                            ((StatefulTargetObject) left).getTargetObject().getAssociationFilter(
                                getAttributes(((StatefulTargetObject) left).getTargetObject())));
                    }
                }
                else {
                    repositoryObject.addAttribute(Association.LEFT_ENDPOINT,
                        left.getAssociationFilter(getAttributes(left)));
                }
            }
            if (right != null) {
                if (right instanceof StatefulTargetObject) {
                    if (((StatefulTargetObject) right).isRegistered()) {
                        repositoryObject.addAttribute(
                            Association.RIGHT_ENDPOINT,
                            ((StatefulTargetObject) right).getTargetObject().getAssociationFilter(
                                getAttributes(((StatefulTargetObject) right).getTargetObject())));
                    }
                }
                else {
                    repositoryObject.addAttribute(Association.RIGHT_ENDPOINT,
                        right.getAssociationFilter(getAttributes(right)));
                }
            }

            // ACE-523 Allow the same semantics as with createAssocation, ca2f, cf2d & cd2t...
            leftAttribute = repositoryObject.getAttribute(Association.LEFT_CARDINALITY);
            rightAttribute = repositoryObject.getAttribute(Association.RIGHT_CARDINALITY);

            if (leftAttribute != null) {
                repositoryObject.addAttribute(Association.LEFT_CARDINALITY, interpretCardinality(leftAttribute));
            }
            if (rightAttribute != null) {
                repositoryObject.addAttribute(Association.RIGHT_CARDINALITY, interpretCardinality(rightAttribute));
            }
        }
    }

    private Map<String, String> getAttributes(RepositoryObject object) {
        Map<String, String> result = new HashMap<>();
        for (Enumeration<String> keys = object.getAttributeKeys(); keys.hasMoreElements();) {
            String key = keys.nextElement();
            result.put(key, object.getAttribute(key));
        }
        return result;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Association<? extends RepositoryObject, ? extends RepositoryObject> createAssocation(String entityType, String leftEntityId, String rightEntityId, String leftCardinality,
        String rightCardinality) {
        Map<String, String> attrs = new HashMap<>();
        Map<String, String> tags = new HashMap<>();
        attrs.put(Association.LEFT_ENDPOINT, leftEntityId);
        attrs.put(Association.LEFT_CARDINALITY, interpretCardinality(leftCardinality));
        attrs.put(Association.RIGHT_ENDPOINT, rightEntityId);
        attrs.put(Association.RIGHT_CARDINALITY, interpretCardinality(rightCardinality));
        return (Association<RepositoryObject, RepositoryObject>) createRepositoryObject(entityType, attrs, tags);
    }

    @Override
    public RepositoryObject getLeft(String entityType, String entityId) {
        if (ARTIFACT2FEATURE.equals(entityType)) {
            return getGenericObjectRepository(ARTIFACT).get(entityId);
        }
        else if (FEATURE2DISTRIBUTION.equals(entityType)) {
            return getGenericObjectRepository(FEATURE).get(entityId);
        }
        else if (DISTRIBUTION2TARGET.equals(entityType)) {
            return getGenericObjectRepository(DISTRIBUTION).get(entityId);
        }
        else {
            // throws an exception in case of an illegal type!
            getGenericObjectRepository(entityType);
        }
        return null;
    }

    @Override
    public RepositoryObject getRight(String entityType, String entityId) {
        if (ARTIFACT2FEATURE.equals(entityType)) {
            return getGenericObjectRepository(FEATURE).get(entityId);
        }
        else if (FEATURE2DISTRIBUTION.equals(entityType)) {
            return getGenericObjectRepository(DISTRIBUTION).get(entityId);
        }
        else if (DISTRIBUTION2TARGET.equals(entityType)) {
            return getGenericObjectRepository(TARGET).get(entityId);
        }
        else {
            // throws an exception in case of an illegal type!
            getGenericObjectRepository(entityType);
        }
        return null;
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void deleteRepositoryObject(String entityType, String entityId) {
        ObjectRepository objectRepository = getGenericObjectRepository(entityType);
        RepositoryObject repositoryObject = objectRepository.get(entityId);
        // ACE-239: avoid null entities being passed in...
        if (repositoryObject == null) {
            throw new IllegalArgumentException("Could not find repository object!");
        }

        objectRepository.remove(repositoryObject);
    }

    private <T extends RepositoryObject> List<T> getGenericRepositoryObjects(String entityType) {
        ObjectRepository<T> repo = getGenericObjectRepository(entityType);
        List<T> list = repo.get();
        if (list != null) {
            return list;
        }
        else {
            return Collections.emptyList();
        }
    }

    @SuppressWarnings("unchecked")
    private <T extends RepositoryObject> ObjectRepository<T> getGenericObjectRepository(String entityType) {
        if (ARTIFACT.equals(entityType)) {
            return (ObjectRepository<T>) m_artifactRepository;
        }
        if (ARTIFACT2FEATURE.equals(entityType)) {
            return (ObjectRepository<T>) m_artifact2FeatureAssociationRepository;
        }
        if (FEATURE.equals(entityType)) {
            return (ObjectRepository<T>) m_featureRepository;
        }
        if (FEATURE2DISTRIBUTION.equals(entityType)) {
            return (ObjectRepository<T>) m_feature2DistributionAssociationRepository;
        }
        if (DISTRIBUTION.equals(entityType)) {
            return (ObjectRepository<T>) m_distributionRepository;
        }
        if (DISTRIBUTION2TARGET.equals(entityType)) {
            return (ObjectRepository<T>) m_distribution2TargetAssociationRepository;
        }
        if (TARGET.equals(entityType)) {
            return (ObjectRepository<T>) m_statefulTargetRepository;
        }
        throw new IllegalArgumentException("Unknown entity type: " + entityType);
    }

    /*** SHELL COMMANDS ***/

    @Override
    public List<ArtifactObject> lrp() {
        return m_artifactRepository.getResourceProcessors();
    }

    @Override
    public List<ArtifactObject> lrp(String filter) throws Exception {
        Filter f = m_context.createFilter(filter);
        List<ArtifactObject> rps = m_artifactRepository.getResourceProcessors();
        List<ArtifactObject> res = new LinkedList<>();
        for (ArtifactObject rp : rps) {
            if (f.matchCase(rp.getDictionary())) {
                res.add(rp);
            }
        }
        return res;
    }

    @Override
    public List<ArtifactObject> la() {
        return getGenericRepositoryObjects(ARTIFACT);
    }

    public List<ArtifactObject> lr() {
        return m_artifactRepository.getResourceProcessors();
    }

    @Override
    public List<ArtifactObject> la(String filter) throws Exception {
        ObjectRepository<ArtifactObject> repo = getGenericObjectRepository(ARTIFACT);
        return repo.get(m_context.createFilter(filter));
    }

    @Override
    public ArtifactObject ca(String url, boolean upload) throws Exception {
        return createArtifact(url, upload);
    }

    public ArtifactObject createArtifact(String url, boolean upload) throws Exception {
        return m_artifactRepository.importArtifact(new URL(url), upload);
    }

    @Override
    public ArtifactObject ca(String name, String url, String bsn, String version) {
        Map<String, String> attrs = new HashMap<>();
        attrs.put(ArtifactObject.KEY_ARTIFACT_NAME, name);
        attrs.put(ArtifactObject.KEY_URL, url);
        attrs.put(ArtifactObject.KEY_MIMETYPE, BundleHelper.MIMETYPE);
        attrs.put("Bundle-SymbolicName", bsn);
        attrs.put("Bundle-Version", version);
        return ca(attrs);
    }

    @Override
    public ArtifactObject ca(Map<String, String> attrs) {
        return ca(attrs, new HashMap<String, String>());
    }

    @Override
    public ArtifactObject ca(Map<String, String> attrs, Map<String, String> tags) {
        return (ArtifactObject) createRepositoryObject(ARTIFACT, attrs, tags);
    }

    @Override
    public void da(ArtifactObject repositoryObject) {
        deleteRepositoryObject(ARTIFACT, repositoryObject.getDefinition());
    }

    @Override
    public void da(String filter) throws Exception {
        for (ArtifactObject object : la(filter)) {
            deleteRepositoryObject(ARTIFACT, object.getDefinition());
        }
    }

    @Override
    public List<Artifact2FeatureAssociation> la2f() {
        return getGenericRepositoryObjects(ARTIFACT2FEATURE);
    }

    @Override
    public List<Artifact2FeatureAssociation> la2f(String filter) throws Exception {
        ObjectRepository<Artifact2FeatureAssociation> repo = getGenericObjectRepository(ARTIFACT2FEATURE);
        return repo.get(m_context.createFilter(filter));
    }

    @Override
    public Artifact2FeatureAssociation ca2f(String left, String right) {
        return ca2f(left, right, "1", "1");
    }

    @Override
    public Artifact2FeatureAssociation ca2f(String left, String right, String leftCardinality, String rightCardinalty) {
        return (Artifact2FeatureAssociation) cas(ARTIFACT2FEATURE, left, right, leftCardinality, rightCardinalty);
    }

    @Override
    public void da2f(Artifact2FeatureAssociation repositoryObject) {
        deleteRepositoryObject(ARTIFACT2FEATURE, repositoryObject.getDefinition());
    }

    @Override
    public void da2f(String filter) throws Exception {
        for (Artifact2FeatureAssociation object : la2f(filter)) {
            deleteRepositoryObject(ARTIFACT2FEATURE, object.getDefinition());
        }

    }

    @Override
    public List<FeatureObject> lf() {
        return getGenericRepositoryObjects(FEATURE);
    }

    @Override
    public List<FeatureObject> lf(String filter) throws Exception {
        ObjectRepository<FeatureObject> repo = getGenericObjectRepository(FEATURE);
        return repo.get(m_context.createFilter(filter));
    }

    @Override
    public FeatureObject cf(String name) {
        Map<String, String> attrs = new HashMap<>();
        attrs.put(FeatureObject.KEY_NAME, name);
        return cf(attrs);
    }

    @Override
    public FeatureObject cf(Map<String, String> attrs) {
        return cf(attrs, new HashMap<String, String>());
    }

    @Override
    public FeatureObject cf(Map<String, String> attrs, Map<String, String> tags) {
        return createFeature(attrs, tags);
    }

    public FeatureObject createFeature(Map<String, String> attrs, Map<String, String> tags) {
        return (FeatureObject) createRepositoryObject(FEATURE, attrs, tags);
    }

    @Override
    public void df(FeatureObject repositoryObject) {
        deleteRepositoryObject(FEATURE, repositoryObject.getDefinition());
    }

    @Override
    public void df(String filter) throws Exception {
        for (FeatureObject object : lf(filter)) {
            deleteRepositoryObject(FEATURE, object.getDefinition());
        }
    }

    @Override
    public List<Feature2DistributionAssociation> lf2d() {
        return getGenericRepositoryObjects(FEATURE2DISTRIBUTION);
    }

    @Override
    public List<Feature2DistributionAssociation> lf2d(String filter) throws Exception {
        ObjectRepository<Feature2DistributionAssociation> repo = getGenericObjectRepository(FEATURE2DISTRIBUTION);
        return repo.get(m_context.createFilter(filter));
    }

    @Override
    public Feature2DistributionAssociation cf2d(String left, String right) {
        return cf2d(left, right, "1", "1");
    }

    @Override
    public Feature2DistributionAssociation cf2d(String left, String right, String leftCardinality, String rightCardinalty) {
        return (Feature2DistributionAssociation) cas(FEATURE2DISTRIBUTION, left, right, leftCardinality, rightCardinalty);
    }

    @Override
    public void df2d(Feature2DistributionAssociation repositoryObject) {
        deleteRepositoryObject(FEATURE2DISTRIBUTION, repositoryObject.getDefinition());
    }

    @Override
    public void df2d(String filter) throws Exception {
        for (Feature2DistributionAssociation object : lf2d(filter)) {
            deleteRepositoryObject(FEATURE2DISTRIBUTION, object.getDefinition());
        }
    }

    @Override
    public List<DistributionObject> ld() {
        return getGenericRepositoryObjects(DISTRIBUTION);
    }

    @Override
    public List<DistributionObject> ld(String filter) throws Exception {
        ObjectRepository<DistributionObject> repo = getGenericObjectRepository(DISTRIBUTION);
        return repo.get(m_context.createFilter(filter));
    }

    @Override
    public DistributionObject cd(String name) {
        Map<String, String> attrs = new HashMap<>();
        attrs.put(DistributionObject.KEY_NAME, name);
        return cd(attrs);
    }

    @Override
    public DistributionObject cd(Map<String, String> attrs) {
        return cd(attrs, new HashMap<String, String>());
    }

    @Override
    public DistributionObject cd(Map<String, String> attrs, Map<String, String> tags) {
        return createDistribution(attrs, tags);
    }

    public DistributionObject createDistribution(Map<String, String> attrs, Map<String, String> tags) {
        return (DistributionObject) createRepositoryObject(DISTRIBUTION, attrs, tags);
    }

    @Override
    public void dd(DistributionObject repositoryObject) {
        deleteRepositoryObject(DISTRIBUTION, repositoryObject.getDefinition());
    }

    @Override
    public void dd(String filter) throws Exception {
        for (DistributionObject object : ld(filter)) {
            deleteRepositoryObject(DISTRIBUTION, object.getDefinition());
        }
    }

    @Override
    public List<Distribution2TargetAssociation> ld2t() {
        return getGenericRepositoryObjects(DISTRIBUTION2TARGET);
    }

    @Override
    public List<Distribution2TargetAssociation> ld2t(String filter) throws Exception {
        ObjectRepository<Distribution2TargetAssociation> repo = getGenericObjectRepository(DISTRIBUTION2TARGET);
        return repo.get(m_context.createFilter(filter));
    }

    @Override
    public Distribution2TargetAssociation cd2t(String left, String right) {
        return cd2t(left, right, "1", "1");
    }

    @Override
    public Distribution2TargetAssociation cd2t(String left, String right, String leftCardinality, String rightCardinalty) {
        return (Distribution2TargetAssociation) cas(DISTRIBUTION2TARGET, left, right, leftCardinality, rightCardinalty);
    }

    @Override
    public void dd2t(Distribution2TargetAssociation repositoryObject) {
        deleteRepositoryObject(DISTRIBUTION2TARGET, repositoryObject.getDefinition());
    }

    @Override
    public void dd2t(String filter) throws Exception {
        for (Distribution2TargetAssociation object : ld2t(filter)) {
            deleteRepositoryObject(DISTRIBUTION2TARGET, object.getDefinition());
        }
    }

    @Override
    public List<StatefulTargetObject> lt() {
        return getGenericRepositoryObjects(TARGET);
    }

    @Override
    public List<StatefulTargetObject> lt(String filter) throws Exception {
        ObjectRepository<StatefulTargetObject> repo = getGenericObjectRepository(TARGET);
        return repo.get(m_context.createFilter(filter));
    }

    @Override
    public StatefulTargetObject ct(String name) {
        Map<String, String> attrs = new HashMap<>();
        attrs.put(StatefulTargetObject.KEY_ID, name);
        return ct(attrs);
    }

    @Override
    public StatefulTargetObject ct(Map<String, String> attrs) {
        return ct(attrs, new HashMap<String, String>());
    }

    @Override
    public StatefulTargetObject ct(Map<String, String> attrs, Map<String, String> tags) {
        return (StatefulTargetObject) createRepositoryObject(TARGET, attrs, tags);
    }

    @Override
    public void dt(StatefulTargetObject repositoryObject) {
        deleteRepositoryObject(TARGET, repositoryObject.getDefinition());
    }

    @Override
    public void dt(String filter) throws Exception {
        for (StatefulTargetObject object : lt(filter)) {
            deleteRepositoryObject(TARGET, object.getDefinition());
        }
    }

    @Override
    public StatefulTargetObject approveTarget(StatefulTargetObject targetObject) {
        targetObject.approve();
        return targetObject;
    }

    @Override
    public StatefulTargetObject registerTarget(StatefulTargetObject targetObject) {
        if (targetObject.isRegistered()) {
            return null;
        }
        targetObject.register();
        return targetObject;
    }
    
    
    @Override
    public void impw(String directoryPath, String exportFileName)  throws Exception {
        try {
        	//-- Load jar artifacts

        	
        	//--
			DocumentBuilderFactory parserFactory = DocumentBuilderFactory.newInstance();
			parserFactory.setNamespaceAware(true);

			DocumentBuilder parser = parserFactory.newDocumentBuilder();
			
			File expFile = new File(directoryPath,exportFileName);
			
			Document doc = parser.parse(expFile);

	        NodeList features = doc.getElementsByTagName("feature");
	        for (int i = 0; i < features.getLength(); ++i) {
	            final Node feature = features.item(i);
	            
	            //-- Create feature
	            String featureId = feature.getAttributes().getNamedItem("id").getNodeValue();
	            final FeatureObject f = cf(featureId);
	            //final String featureId = DOMUtil.getChildText(DOMUtil.getFirstChildElement(feature,"id"));
	            NodeList artifacts = feature.getChildNodes();
	            for (int j=0; j<artifacts.getLength(); ++j) {
		            final Node art = features.item(j);
		            final String artId = DOMUtil.getChildText(DOMUtil.getFirstChildElement(art, "id"));	            	
	            }
/*	            final Node layer = layers.item(i + 1);
	            String resolutions = DOMUtil.getChildText(DOMUtil.getFirstChildElement(tileSet, "Resolutions"));
	            int width = Integer.parseInt(DOMUtil.getChildText(DOMUtil.getFirstChildElement(tileSet, "Width")));
	            int height = Integer.parseInt(DOMUtil.getChildText(DOMUtil.getFirstChildElement(tileSet, "Height")));
	            Element bbox = DOMUtil.getFirstChildElement(layer, "BoundingBox");
	            float minX = Float.parseFloat(DOMUtil.getAttrValue(bbox, "minx"));
	            float minY = Float.parseFloat(DOMUtil.getAttrValue(bbox, "miny"));
	            float maxX = Float.parseFloat(DOMUtil.getAttrValue(bbox, "maxx"));
	            float maxY = Float.parseFloat(DOMUtil.getAttrValue(bbox, "maxy"));
	            String format = DOMUtil.getChildText(DOMUtil.getFirstChildElement(tileSet, "Format"));

	            String layerName = DOMUtil.getChildText(DOMUtil.getFirstChildElement(layer, "Name"));
	            final TileCacheLayerInfo info = new TileCacheLayerInfo(resolutions, width, height, minX, minY, maxX, maxY, format);
	            result.tileCacheLayers.put(layerName, info);*/
	        }			
		} catch (Exception e) {
			throw e;
		}   	
    }

    public static Version getVersion(Resource resource) {
        Map<String, Object> attrs = getNamespaceAttributes(resource, "osgi.identity");
        if (attrs == null)
            return Version.emptyVersion;
        Version version = (Version) attrs.get("version");
        return version == null ? Version.emptyVersion : version;
    }

    public static List<Version> getVersions(List<Resource> resources) {
        List<Version> versions = new ArrayList<>();
        for (Resource resource : resources) {
            versions.add(getVersion(resource));
        }
        return versions;
    }

    public static String getType(Resource resource) {
        Map<String, Object> attrs = getNamespaceAttributes(resource, "osgi.identity");
        if (attrs == null)
            return null;
        return (String) attrs.get("type");
    }

    public static String getUrl(Resource resource) {
        Map<String, Object> attrs = getNamespaceAttributes(resource, "osgi.content");
        if (attrs == null)
            return null;
        URI url = (URI) attrs.get("url");
        return url == null ? null : url.toString();
    }

    public static String getMimetype(Resource resource) {
        Map<String, Object> attrs = getNamespaceAttributes(resource, "osgi.content");
        if (attrs == null)
            return null;

        String mime = (String) attrs.get("mime");
        if (mime == null) {
            // FIXME this is a work around for OBR not supporting mimetype
            String url = getUrl(resource);
            if (url.endsWith(".jar")) {
                mime = "application/vnd.osgi.bundle";
            }
            else if (url.endsWith(".xml")) {
                mime = "application/xml:osgi-autoconf";
            }
        }
        return mime;
    }
    
    private static Map<String, Object> getNamespaceAttributes(Resource resource, String namespace) {
        List<Capability> caps = resource.getCapabilities(namespace);
        if (caps.isEmpty())
            return null;
        Map<String, Object> attrs = caps.get(0).getAttributes();
        if (attrs == null)
            return null;
        return attrs;
    }    
    
    @Override
    public String expw(String id, String directoryPath) throws Exception {
    	String brName = id+".bndrun";
    	StringBuilder brsb = new StringBuilder();
    	brsb.append("-include: \\\n");
    	

		StringBuilder sb = new StringBuilder();
		sb.append("<?xml version=\"1.0\"?>");
    	try {
			DPHelper dhelper = new DPHelper(this, m_log);
        	
        	// download dists    		
			Map<String,String> fmap = new HashMap<String,String>();
			sb.append("<repository id=\""+id+"\">");

        	//downloads targets
			List<StatefulTargetObject> tgts = lt();
			sb.append("<targets>");
			for (StatefulTargetObject tgt : tgts) {
				String tName = tgt.getID();
				sb.append("<target id=\""+tName+"\">");
				List<Distribution2TargetAssociation> d2tList = ld2t("(leftEndpoint=*name="+tName+"*)");
				sb.append("<distributionrefs>");
				for (Distribution2TargetAssociation d2t : d2tList) {
					Enumeration<String> keys = d2t.getAttributeKeys();
					String dName = d2t.getAttribute("leftEndpoint");
					List<DistributionObject> ld = ld(dName);
					if (ld.size() > 0) {
						dName = ld.get(0).getName();
						fmap.put(dName,downloadFeature(directoryPath,dName,dhelper));
						sb.append("<distributionref refid=\""+dName+"\">");
						sb.append("</distributionref>");						
					}
				}
				sb.append("</distributionrefs>");

				Enumeration<String> tkeys = null;
				try {
					tkeys = tgt.getTagKeys();
				} catch (Exception e) {
				}
				if (tkeys != null) {
					sb.append("<tags>");
					while (tkeys.hasMoreElements()) {
						String key = tkeys.nextElement();
						sb.append("<tag name=\""+key+"\" value=\""+tgt.getTag(key)+"\"/>");
					}
					sb.append("</tags>");			
				}
				sb.append("</target>");
			}
			
			sb.append("</targets>");
			
			
			sb.append("<distributions>");
			List<DistributionObject> dists = ld();
			for (DistributionObject dobj : dists) {
				String dName = dobj.getName();
				sb.append("<distribution id=\""+dName+"\">");
				
				sb.append("<featurerefs>");
				List<Feature2DistributionAssociation> f2dList = lf2d("(rightEndpoint=*name="+dName+"*)");
				for (Feature2DistributionAssociation f2d : f2dList) {
					Enumeration<String> keys = f2d.getAttributeKeys();
					String fName = f2d.getAttribute("leftEndpoint");
					List<FeatureObject> lf = lf(fName);
					if (lf.size() > 0) {
						fName = lf.get(0).getName();
						fmap.put(fName,downloadFeature(directoryPath,fName,dhelper));
						sb.append("<featureref refid=\""+fName+"\">");
						sb.append("</featureref>");
					}
				}
				sb.append("</featurerefs>");
				
				sb.append("</distribution>");
			}
			
			StringBuilder fsb = new StringBuilder();
			fsb.append("<features>");
			String ENDOL = ",\\\n";
			for (String f : fmap.keySet()) {
				fsb.append(fmap.get(f));
				brsb.append("\t"+f+".bndrun"+ENDOL);
			}
			fsb.append("</features>");
			
			sb.append("</distributions>");
			sb.append(fsb.toString());
			sb.append("</repository>");
			
			dhelper.writeTextContents(directoryPath, id+".xml", sb.toString());
			dhelper.writeTextContents(directoryPath, brName, brsb.toString());
			
			return sb.toString();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
    }       

    private String downloadFeature(String directoryPath, String fName, DPHelper dhelper) throws Exception {
    	SimpleDateFormat df = new SimpleDateFormat("YYYYMMDDHHmm");//201508261740
    	Pattern pattern = Pattern.compile("(?<![\\d.])(\\d+[.])+(\\d+)(?![\\d.])?");
    	
    	String featureBndrun = fName+".bndrun";
    	StringBuilder brsb = new StringBuilder();
    	String bndrunFirstLine = "-runbundles."+fName+": \\\n";
		brsb.append(bndrunFirstLine);
    	
    	StringBuilder fsb = new StringBuilder();
    	fsb.append("<feature id=\""+fName+"\">");
    	
    	
    	boolean isJar = true;
    	List<Artifact2FeatureAssociation> arts = la2f("(rightEndpoint=*name="+fName+"*)");
    	String ENDOL = ",\\\n";
    	String url = null;
		for (Artifact2FeatureAssociation art : arts) {
    		String le = art.getAttribute("leftEndpoint");
    		//Enumeration<String> keys = art.getAttributeKeys();
    		//String aName = art.getAttribute("Bundle-SymbolicName");
    		//String ver = art.getAttribute("Bundle-Version");
    		List<ArtifactObject> ds = la(le);
    		if (ds.size() > 0) {
				ArtifactObject a = ds.get(0);
				Enumeration<String> aks = a.getAttributeKeys();
	    		url = a.getURL();
	    		String name = a.getAttribute("Bundle-SymbolicName");
	    		String ver = a.getAttribute("Bundle-Version"); 
	    		String id = null;
	    		if (name == null) {
	    			isJar = false;
	    			name = a.getAttribute("filename");
	    	   		fsb.append("<artifact id=\""+name+"\" name=\""+name+"\">");
	    		}
	    		else {
	    			isJar = true;
	    			id = name; 
	    			name += "-"+ver+".jar";
	    	   		fsb.append("<artifact symbolicname=\""+id+"\" id=\""+id+"\" name=\""+name+"\" version=\""+ver+"\">");
	    		}
	    		
	    		
	    		File file = dhelper.downloadArtifactContents(isJar, directoryPath, name, url);
	    		if (isJar) {
		            JarInputStream jis = new JarInputStream(new FileInputStream(file));
		            String jarVer = jis.getManifest().getMainAttributes().getValue("Bundle-Version");
		            //String urlJarVer = jis.getManifest().getMainAttributes().getValue("Bundle-Version");
		            String urlJarVer = deriveVersion(df,pattern,url,jarVer,ver);
		            jarVer = removeTS(df,urlJarVer);
	    	   		brsb.append("\t"+id+";version=\"["+jarVer+","+urlJarVer+"]\""+ENDOL);
	    		}
	    		
	   	
	    		fsb.append("</artifact>");
    		}
    	}
    	
    	fsb.append("</feature>");
    	
    	String bndrunContent = brsb.toString();
    	int index = bndrunContent.lastIndexOf(ENDOL);
    	if (index >= 0)
    		bndrunContent = bndrunContent.substring(0,index);
		dhelper.writeTextContents(directoryPath,featureBndrun,bndrunContent);
    	
    	return fsb.toString();
	}

	private String deriveVersion(SimpleDateFormat df, Pattern pattern, String url, String jarVer, String ver) {
		int jarIndex = url.lastIndexOf("/");
		String jarName = url.substring(jarIndex+1);
		int extIndex = jarName.lastIndexOf(".");
		String jarNameVer = jarName.substring(0,extIndex);
		
		String jarFileVer = null;
    	try {
			Matcher matcher = pattern.matcher(jarNameVer);
			if (matcher.find()) {
				jarFileVer = matcher.group(0);		
			}
			else {
		        if (jarFileVer == null) {
		        	jarFileVer = null;
		        }					
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//int verIndex = jarNameVer.indexOf("-");
		//String jarFileVer = jarNameVer.substring(verIndex+1);
		
/*		String[] tokens = jarNameVer.split("-");
		String jarFileVer = null;
		if (tokens.length == 2) { 
			jarFileVer = tokens[1];
		}
		else if (tokens.length == 3) {
			jarFileVer = tokens[2];
		}
		else {
			jarFileVer = jarNameVer.substring(jarNameVer.lastIndexOf("-")+1);
		}*/

        
		return jarFileVer;
	}

	private String removeTS(SimpleDateFormat df,  String jarVer) {
		int li = jarVer.lastIndexOf('.');
		if (li < 0)
			return jarVer;
		
		String potentialTS = jarVer.substring(li+1);
		
		//Is TS
		try {
			df.parse(potentialTS);
			jarVer = jarVer.substring(0,li);
			return jarVer;
		} catch (ParseException e) {
		}
		
		//Is not number
		if (!potentialTS.matches("[-+]?\\d*\\.?\\d+")) {
			jarVer = jarVer.substring(0,li);
			return jarVer;
		}
		
		String[] tokens = jarVer.split("\\.");
		if (tokens.length > 3)
			jarVer = tokens[0]+"."+tokens[1]+"."+tokens[2];
		
		return jarVer;
	}

	@Override
    public boolean isModified() throws IOException {
        return m_repositoryAdmin.isModified();
    }

    @Override
    public boolean isCurrent() throws IOException {
        return m_repositoryAdmin.isCurrent();
    }

    @Override
    public Association<? extends RepositoryObject, ? extends RepositoryObject> cas(String entityType, String leftEntityId, String rightEntityId, String leftCardinality, String rightCardinality) {
        return createAssocation(entityType, leftEntityId, rightEntityId, leftCardinality, rightCardinality);
    }

    private static String interpretCardinality(String cardinality) {
        if (cardinality != null && "N".equals(cardinality.toUpperCase())) {
            return "" + Integer.MAX_VALUE;
        }
        else {
            return cardinality;
        }
    }

    @Override
    public String toString() {
        return getSessionID();
    }

	@Override
	public void cpytgs(RepositoryObject src, RepositoryObject tgt)
			throws Exception {
		Enumeration<String> en = src.getTagKeys();
		while (en.hasMoreElements()) {
			final String tag = en.nextElement();
			final String val = src.getTag(tag);
			tgt.addTag(tag, val);
		}
		
	}
}
