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
package org.apache.ace.client.repository.helper.configuration.impl;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.ace.client.repository.helper.ArtifactPreprocessor;
import org.apache.ace.client.repository.helper.ArtifactRecognizer;
import org.apache.ace.client.repository.helper.base.VelocityArtifactPreprocessor;
import org.apache.ace.client.repository.helper.configuration.ConfigurationHelper;
import org.apache.ace.client.repository.object.ArtifactObject;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class ConfigurationHelperImpl implements ArtifactRecognizer, ConfigurationHelper {

    // known valid metatype namespaces
    private static final String NAMESPACE_1_0 = "http://www.osgi.org/xmlns/metatype/v1.0.0";
    private static final String NAMESPACE_1_1 = "http://www.osgi.org/xmlns/metatype/v1.1.0";
    private static final String NAMESPACE_1_2 = "http://www.osgi.org/xmlns/metatype/v1.2.0";

    private final SAXParserFactory m_saxParserFactory;

    public ConfigurationHelperImpl() {
        m_saxParserFactory = SAXParserFactory.newInstance();
        m_saxParserFactory.setNamespaceAware(false);
        m_saxParserFactory.setValidating(false);
    }
    
    public boolean canHandle(String mimetype) {
        return MIMETYPE.equals(mimetype);
    }

    public Map<String, String> extractMetaData(URL artifact) throws IllegalArgumentException {
        Map<String, String> result = new HashMap<String, String>();
        result.put(ArtifactObject.KEY_PROCESSOR_PID, PROCESSOR);
        result.put(ArtifactObject.KEY_MIMETYPE, MIMETYPE);
        String name = new File(artifact.getFile()).getName();
        String key = KEY_FILENAME + "-";
        int idx = name.indexOf(key);
        if (idx > -1) {
            int endIdx = name.indexOf("-", idx + key.length());
            name = name.substring(idx + key.length(), (endIdx > -1) ? endIdx : (name.length() - getExtension(artifact).length()));
        }
        result.put(ArtifactObject.KEY_ARTIFACT_NAME, name);
        result.put(KEY_FILENAME, name);
        return result;
    }

    public String recognize(URL artifact) {
        MetaDataNamespaceCollector handler = new MetaDataNamespaceCollector();
        InputStream input = null;
        try {
            input = artifact.openStream();
            SAXParser parser = m_saxParserFactory.newSAXParser();
            parser.parse(input, handler);
        }
        catch (Exception e) {
            String namespace = handler.getMetaDataNamespace();
            if (namespace != null
                && (namespace.equals(NAMESPACE_1_0)
                    || namespace.equals(NAMESPACE_1_1)
                    || namespace.equals(NAMESPACE_1_2))) {
                return MIMETYPE;
            }
        }
        finally {
            if (input != null) {
                try {
                    input.close();
                }
                catch (IOException e) {}
            }
        }
        return null;
    }

    public boolean canUse(ArtifactObject object) {
        return MIMETYPE.equals(object.getMimetype());
    }

    public Map<String, String> checkAttributes(Map<String, String> attributes) {
        // All necessary checks will be done by the constructor using getMandatoryAttributes.
        return attributes;
    }

    public <TYPE extends ArtifactObject> String getAssociationFilter(TYPE obj, Map<String, String> properties) {
        return "(" + KEY_FILENAME + "=" + obj.getAttribute(KEY_FILENAME) + ")";
    }

    public <TYPE extends ArtifactObject> int getCardinality(TYPE obj, Map<String, String> properties) {
        return Integer.MAX_VALUE;
    }

    public Comparator<ArtifactObject> getComparator() {
        return null;
    }

    public String[] getDefiningKeys() {
        return new String[] {KEY_FILENAME};
    }

    public String[] getMandatoryAttributes() {
        return new String[] {KEY_FILENAME};
    }

    private final static VelocityArtifactPreprocessor VELOCITY_ARTIFACT_PREPROCESSOR = new VelocityArtifactPreprocessor();
    public ArtifactPreprocessor getPreprocessor() {
        return VELOCITY_ARTIFACT_PREPROCESSOR;
    }
    
    public String getExtension(URL artifact) {
        return ".xml";
    }

    static class MetaDataNamespaceCollector extends DefaultHandler {

        private String m_metaDataNameSpace = "";

        public String getMetaDataNamespace() {
            return m_metaDataNameSpace;
        }

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes)
            throws SAXException {
            if (qName.equals("MetaData") || qName.endsWith(":MetaData")) {
                String nsAttributeQName = "xmlns";
                if (qName.endsWith(":MetaData")) {
                    nsAttributeQName = "xmlns" + ":" + qName.split(":")[0];
                }
                for (int i = 0; i < attributes.getLength(); i++) {
                    if (attributes.getQName(i).equals(nsAttributeQName)) {
                        m_metaDataNameSpace = attributes.getValue(i);
                    }
                }
            }
            // first element is expected to have been the MetaData
            // root so we can now terminate processing.
            throw new SAXException("Done");
        }
    }
}