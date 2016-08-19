package com.vmware.fdmsecprotomgmt;

import java.util.Arrays;
import java.util.List;

/**
 * Entry point into the ESXi - vSphere HA (FDM) SSL Security protocol configuration tool
 *
 * Copyright (c) 2016
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * @author Gururaja Hegdal (ghegdal@vmware.com)
 * @version 1.0
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
public class RunApp
{
    /**
     * Usage method - how to use/invoke the script, reveals the options supported through this script
     */
    public static void usageSSLScript()
    {
        System.out.println("\n~~~~~~~~~~~~~~~~~~~~~~~~~~ SSLv3 CONFIGURATION ~~~~~~~~~~~~~~~~~~~~~~~~~~");
        System.out.println(
            "Usage: java -jar fdmsecprotomgmt.jar --vsphereip <vCenter Server IP> --username <uname> --password <pwd> --hostsinfofile <pathToHostsListfile> [enablessl] [disablessl]");
        System.out.println("\nExample : To enable SSLv3 on One or More vSphere HA enabled Cluster & its ESXi hosts");
        System.out.println(
            "\"java -jar fdmsecprotomgmt.jar --vsphereip 10.1.2.3 --username adminUser --password dummy --hostsinfofile c:\\SecurityProtoMgmt\\clusteresxihosts.csv enablessl\"");
        System.out.println("\nExample : To disable SSLv3 on One or More vSphere HA enabled Cluster & its ESXi hosts");
        System.out.println(
            "\"java -jar fdmsecprotomgmt.jar --vsphereip 10.1.2.3 --username adminUser --password dummy --hostsinfofile c:\\SecurityProtoMgmt\\clusteresxihosts.csv disablessl\"");

        System.out.println("\nYou can obtain hosts file information, by using 'secprotomgmt.jar' utility");
    }

    /**
     * Main entry point into the SSL Script
     */
    public static void main(String[] args) {

        System.out
            .println("######################### SSL/TLS Configuration Script execution STARTED #########################");

        // Read command line arguments
        if (args.length > 0 && args.length >= 7) {
            List<String> cmdLineArgs = Arrays.asList(args);
            if (cmdLineArgs.contains("enablessl") || cmdLineArgs.contains("disablessl")){
                // Request is for SSL configuration
                ESXi5xFDMSSLConfigUpdater fdmSslScript = new ESXi5xFDMSSLConfigUpdater(args);
                if (fdmSslScript.validateProperties() && fdmSslScript.validatevSphereVersion()) {
                    // Check protocol Consistency across vSphere
                        fdmSslScript.applySSLConfigOnClusters();
                }
            } else {
                usageSSLScript();
            }
        } else {
            usageSSLScript();
        }
        try {
            Thread.sleep(1000 * 2);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println(
            "######################### SSL/TLS Configuration Script execution completed #########################");
    }
}