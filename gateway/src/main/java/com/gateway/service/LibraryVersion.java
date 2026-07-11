package com.gateway.service;

/**
 * Library version configuration for ysoserial compatibility
 * Maps gadget chains to their required library versions
 */
public class LibraryVersion {

    /**
     * Version mappings for each gadget chain
     * Maps to library versions used in BeanShell1, CommonsCollections, etc.
     */
    public static final String getVersion(String gadget) {
        switch (gadget) {
            case "BeanShell1":
                return "1.9.4";
            case "CommonsCollections1":
            case "CommonsCollections2":
            case "CommonsCollections3":
            case "CommonsCollections4":
            case "CommonsCollections5":
            case "CommonsCollections6":
            case "CommonsCollections7":
                return "3.2.1";
            case "Groovy1":
                return "2.4.15";
            case "Groovy2":
                return "2.4.15";
            case "Hibernate1":
                return "5.3.16.Final";
            case "Hibernate2":
                return "5.4.10.Final";
            case "Jdk7u21":
                return "8u45";
            case "C3P0":
                return "0.9.5.5";
            case "JNDI":
                return "3.2.5.7";
            case "Myfaces1":
                return "1.2.12";
            case "Myfaces2":
                return "2.1.9";
            case "Spring1":
            case "Spring2":
                return "5.0.5.RELEASE";
            default:
                return "1.9.4"; // Default for Java 8
        }
    }

    /**
     * Check if gadget is valid
     */
    public static boolean isValidGadget(String gadget) {
        return getVersion(gadget) != null;
    }

    /**
     * Get library group for a gadget
     */
    public static String getLibrary(String gadget) {
        if (gadget == null) return null;

        String version = getVersion(gadget);
        if (version.startsWith("1.9.")) {
            // New style Commons-Collections (3.2.x+)
            return "org.apache.commons";
        } else if (version.startsWith("3.2.")) {
            // Commons-Collections 3.2.2.x
            return "org.apache.commons";
        } else if (version.startsWith("2.")) {
            // Java 2.0.x
            return "sun.misc";
        } else if (version.startsWith("5.")) {
            return "org.hibernate";
        } else if (version.startsWith("2.4.")) {
            return "org.apache.groovy";
        } else if (version.startsWith("7.0.")) {
            return "com.sun";
        } else {
            return "org.apache.commons"; // Default
        }
    }

    /**
     * Get artifact ID for a gadget
     */
    public static String getArtifactId(String gadget) {
        if (gadget == null) return null;

        String version = getVersion(gadget);
        if (gadget.contains("Shell")) {
            return "commons-beanutils";
        } else if (gadget.contains("Groovy")) {
            return "groovy";
        } else if (gadget.contains("Hibernate")) {
            return "hibernate-core";
        } else {
            return "commons-collections";
        }
    }
}