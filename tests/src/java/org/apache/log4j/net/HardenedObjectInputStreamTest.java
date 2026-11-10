/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    /**
     * Nesting depth of the attack payloads. Without the collection count
     * limit, deserializing such a payload needs about 2^DEPTH hashCode()
     * calls, i.e. it never completes.
     */
    private static final int DEPTH = 100;

    /**
     * Time a rejected payload is given to be rejected. A vulnerable
     * implementation spins in hashCode() and never returns, so the test
     * fails instead of hanging the build.
     */
    private static final long TIMEOUT_MILLIS = 20000;

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        // Build the CVE-2023-26464 attack payload: deeply nested HashSets
        // that form a DAG causing O(2^N) hashCode() computation
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        byte[] serialized = serialize(root);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            hois.readObject();
            fail("Deeply nested HashSet should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            // Our resolveObject-based collection count limit caught it (pre-JDK 9)
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") != -1);
        } catch (java.io.InvalidClassException e) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first
            // with "filter status: REJECTED". Either way, the attack is blocked.
        } finally {
            hois.close();
        }
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }

    /**
     * CVE-2023-26464 with deeply nested Hashtables, the collection type
     * log4j itself uses for the MDC of a LoggingEvent.
     */
    public void testDeeplyNestedHashtableRejected() throws Exception {
        byte[] serialized = serialize(nestedMapPayload(true));
        assertRejected(readWithTimeout(new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0])));
    }

    /**
     * CVE-2023-26464 with deeply nested HashMaps.
     */
    public void testDeeplyNestedHashMapRejected() throws Exception {
        byte[] serialized = serialize(nestedMapPayload(false));
        assertRejected(readWithTimeout(new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0])));
    }

    /**
     * CVE-2023-26464 through the path used by SocketNode (SocketServer,
     * SimpleSocketServer) and the chainsaw LoggingReceiver: a LoggingEvent
     * whose MDC carries the nested HashSet payload, read with
     * HardenedLoggingEventInputStream.readAdaptedObject().
     */
    public void testNestedPayloadInLoggingEventMdcRejected() throws Exception {
        Map properties = new HashMap();
        properties.put("payload", nestedSetPayload());
        byte[] serialized = serialize(newEvent("attack", properties));

        assertRejected(readWithTimeout(new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(serialized))));
    }

    /**
     * CVE-2023-26464 variant: a nested graph of Map.Entry objects
     * (java.util.AbstractMap.SimpleEntry, whose hashCode() combines the
     * hashCode() of its key and value) held by a single HashSet. Only one
     * collection is involved, so Map.Entry instances must be counted too.
     */
    public void testNestedMapEntryGraphRejected() throws Exception {
        Map.Entry a = new AbstractMap.SimpleEntry("foo", "bar");
        Map.Entry b = new AbstractMap.SimpleEntry("bar", "foo");
        for (int i = 0; i < DEPTH; i++) {
            Map.Entry nextA = new AbstractMap.SimpleEntry(a, b);
            Map.Entry nextB = new AbstractMap.SimpleEntry(b, a);
            a = nextA;
            b = nextB;
        }
        // insert the holder while it is cheap to hash, then attach the graph
        Map.Entry holder = new AbstractMap.SimpleEntry("root", null);
        Set root = new HashSet();
        root.add(holder);
        holder.setValue(a);
        byte[] serialized = serialize(root);

        assertRejected(readWithTimeout(new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0])));
    }

    /**
     * SocketNode and the chainsaw LoggingReceiver read every event of a
     * connection from the same stream. readAdaptedObject() must give each
     * event its own collection budget so that long-lived connections keep
     * working.
     */
    public void testReadAdaptedObjectResetsCollectionBudget() throws Exception {
        int eventCount = HardenedObjectInputStream.MAX_COLLECTION_COUNT * 2;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < eventCount; i++) {
            Map properties = new HashMap();
            properties.put("user", "alice");
            properties.put("index", String.valueOf(i));
            oos.writeObject(newEvent("message " + i, properties));
        }
        oos.close();

        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(bos.toByteArray()));
        try {
            for (int i = 0; i < eventCount; i++) {
                LoggingEvent event = (LoggingEvent) hleis.readAdaptedObject();
                assertEquals("message " + i, event.getMessage());
                assertEquals(String.valueOf(i), event.getMDC("index"));
                assertEquals("alice", event.getMDC("user"));
            }
        } finally {
            hleis.close();
        }
    }

    private LoggingEvent newEvent(String message, Map properties) {
        Logger logger = Logger.getLogger(HardenedObjectInputStreamTest.class);
        return new LoggingEvent(Logger.class.getName(), logger,
                System.currentTimeMillis(), Level.INFO, message, "main",
                null, null, null, properties);
    }

    /**
     * The nested HashSet payload of the logback advisory.
     */
    private Set nestedSetPayload() {
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < DEPTH; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    /**
     * Same shape as the nested HashSet payload, built with Hashtable or
     * HashMap keys.
     */
    private Map nestedMapPayload(boolean hashtable) {
        Map root = newMap(hashtable);
        Map s1 = root;
        Map s2 = newMap(hashtable);
        for (int i = 0; i < DEPTH; i++) {
            Map t1 = newMap(hashtable);
            Map t2 = newMap(hashtable);
            t1.put("foo", "bar");
            s1.put(t1, "v");
            s1.put(t2, "v");
            s2.put(t1, "v");
            s2.put(t2, "v");
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    private Map newMap(boolean hashtable) {
        return hashtable ? (Map) new Hashtable() : (Map) new HashMap();
    }

    /**
     * Reads one object with readAdaptedObject() on a separate thread and
     * returns what it threw (null when it completed normally). Fails when
     * the read does not finish within TIMEOUT_MILLIS.
     */
    private Throwable readWithTimeout(final HardenedObjectInputStream hois)
            throws InterruptedException {
        final Throwable[] outcome = new Throwable[1];
        final boolean[] done = new boolean[1];
        Thread reader = new Thread(new Runnable() {
            public void run() {
                Throwable thrown = null;
                try {
                    hois.readAdaptedObject();
                } catch (Throwable t) {
                    thrown = t;
                }
                synchronized (outcome) {
                    outcome[0] = thrown;
                    done[0] = true;
                }
            }
        });
        reader.setDaemon(true);
        reader.start();
        reader.join(TIMEOUT_MILLIS);
        synchronized (outcome) {
            if (!done[0]) {
                fail("Deserialization did not complete within " + TIMEOUT_MILLIS
                        + " ms: exponential hashCode() computation (CVE-2023-26464)");
            }
            return outcome[0];
        }
    }

    private void assertRejected(Throwable thrown) {
        if (thrown instanceof InvalidObjectException) {
            assertTrue("Should mention collection limit: " + thrown.getMessage(),
                    thrown.getMessage().indexOf("collection") != -1);
        } else if (!(thrown instanceof java.io.InvalidClassException)) {
            // On JDK 9+, a built-in ObjectInputFilter may reject the payload
            // with an InvalidClassException instead. Anything else means the
            // payload was not rejected.
            fail("Nested payload should be rejected due to collection count limit, got: "
                    + thrown);
        }
    }
}
