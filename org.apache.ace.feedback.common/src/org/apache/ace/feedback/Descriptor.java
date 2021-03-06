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
package org.apache.ace.feedback;

import java.util.NoSuchElementException;
import java.util.StringTokenizer;

import org.apache.ace.range.SortedRangeSet;
import org.apache.ace.feedback.util.Codec;

/**
 * Instances of this class represent a range of events. Such a range is defined by:
 * <ul>
 * <li>A unique target ID</li>
 * <li>A storeID unique for this target</li>
 * <li>A set of event IDs</li>
 * </ul>
 */
public class Descriptor {
    private final SortedRangeSet m_rangeSet;
    private final long m_storeID;
    private final String m_targetID;

    /**
     * Create an event range.
     *
     * @param targetID The unique target ID
     * @param storeID The unique ID for this target
     * @param rangeSet The set of event IDs
     */
    public Descriptor(String targetID, long storeID, SortedRangeSet rangeSet) {
        m_targetID = targetID;
        m_storeID = storeID;
        m_rangeSet = rangeSet;
    }

    /**
     * Create a event range from a string representation. String representations
     * should be formatted as "targetID,storeID,eventIDs" where each substring is formatted
     * using <code>Codec.encode(string)</code> method.
     *
     * Throws an <code>IllegalArgumentException</code> when the string representation is not correctly formatted.
     *
     * @param representation String representation of the event range
     */
    public Descriptor(String representation) {
        try {
            StringTokenizer st = new StringTokenizer(representation, ",");
            m_targetID = Codec.decode(st.nextToken());
            m_storeID = Long.parseLong(st.nextToken());
            String rangeSet = "";
            if (st.hasMoreTokens()) {
                rangeSet = st.nextToken();
            }
            m_rangeSet = new SortedRangeSet(Codec.decode(rangeSet));
        }
        catch (NoSuchElementException e) {
            throw new IllegalArgumentException("Could not create range from: " + representation);
        }
    }

    /**
     * Get the unique target identifier.
     *
     * @return Unique target identifier.
     */
    public String getTargetID() {
        return m_targetID;
    }

    /**
     * Get the unique storeID identifier for this target.
     *
     * @return Unique storeID identifier for this target.
     */
    public long getStoreID() {
        return m_storeID;
    }

    /**
     * Get the range set of the event range.
     *
     * @return The range set
     */
    public SortedRangeSet getRangeSet() {
        return m_rangeSet;
    }

    /**
     * Get a string representation of the event range. String representations
     * generated by this method can be used to construct new <code>Descriptor</code> instances.
     *
     * @return A string representation of the event range
     */
    public String toRepresentation() {
        StringBuffer result = new StringBuffer();
        result.append(Codec.encode(m_targetID));
        result.append(',');
        result.append(m_storeID);
        result.append(',');
        result.append(Codec.encode(m_rangeSet.toRepresentation()));
        return result.toString();
    }
}