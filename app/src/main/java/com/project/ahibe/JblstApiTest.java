package com.project.ahibe;

import java.lang.reflect.Method;
import java.lang.reflect.Constructor;

/**
 * Diagnostic tool to discover jblst API methods.
 */
public class JblstApiTest {
    public static void main(String[] args) {
        try {
            System.out.println("=== JBLST API Discovery ===\n");
            
            // Check P1 class
            Class<?> p1Class = Class.forName("supranational.blst.P1");
            System.out.println("P1 class found: " + p1Class.getName());
            
            System.out.println("\n--- P1 Constructors ---");
            for (Constructor<?> c : p1Class.getDeclaredConstructors()) {
                System.out.println("  " + c);
            }
            
            System.out.println("\n--- P1 Methods ---");
            for (Method m : p1Class.getDeclaredMethods()) {
                System.out.println("  " + m.getName() + " : " + java.util.Arrays.toString(m.getParameterTypes()));
            }
            
            // Check P2 class
            Class<?> p2Class = Class.forName("supranational.blst.P2");
            System.out.println("\n--- P2 Methods ---");
            for (Method m : p2Class.getDeclaredMethods()) {
                if (m.getName().contains("hash")) {
                    System.out.println("  " + m.getName() + " : " + java.util.Arrays.toString(m.getParameterTypes()));
                }
            }
            
            // Try to find hash_to or similar methods
            System.out.println("\n--- Looking for hash methods ---");
            for (Method m : p1Class.getDeclaredMethods()) {
                if (m.getName().toLowerCase().contains("hash")) {
                    System.out.println("  P1." + m.getName() + "(" + java.util.Arrays.toString(m.getParameterTypes()) + ") -> " + m.getReturnType().getSimpleName());
                }
            }
            
        } catch (ClassNotFoundException e) {
            System.err.println("jblst library not found: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

