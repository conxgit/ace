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
package org.apache.ace.client.services;

import java.io.Serializable;

/**
 * Value object for communicating bundle status between the server and the client.
 */
public class BundleDescriptor implements Serializable {
    /**
     * Generated serialVersionUID
     */
    private static final long serialVersionUID = 6017517453464153123L;
    
    private String m_name;
    
    public BundleDescriptor() {}

    public BundleDescriptor(String name) {
        m_name = name;
    }

    public String getName() {
        return m_name;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj.getClass().equals(getClass())) {
            return m_name.equals(((BundleDescriptor) obj).m_name);
        }
        return false;
    }
    
    @Override
    public int hashCode() {
        return m_name.hashCode();
    }
}