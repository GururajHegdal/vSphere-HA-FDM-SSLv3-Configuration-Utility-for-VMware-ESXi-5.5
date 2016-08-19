package com.vmware.fdmsecprotomgmt;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;

import com.vmware.vim25.ClusterConfigInfo;
import com.vmware.vim25.ClusterConfigInfoEx;
import com.vmware.vim25.ClusterConfigSpecEx;
import com.vmware.vim25.ClusterDasConfigInfo;
import com.vmware.vim25.HostRuntimeInfo;
import com.vmware.vim25.HostService;
import com.vmware.vim25.HostSystemConnectionState;
import com.vmware.vim25.OptionValue;
import com.vmware.vim25.TaskInfoState;
import com.vmware.vim25.mo.ClusterComputeResource;
import com.vmware.vim25.mo.HostServiceSystem;
import com.vmware.vim25.mo.HostSystem;
import com.vmware.vim25.mo.InventoryNavigator;
import com.vmware.vim25.mo.ManagedEntity;
import com.vmware.vim25.mo.ServiceInstance;
import com.vmware.vim25.mo.Task;

import ch.ethz.ssh2.Connection;

/**
 * Utility method to enable/disable SSLv3 security protocol for vSphere HA/FDM Port (8182)
 * on VMware vCenter Server 5.5U3b / ESXi 5.5P07 and above release.
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

public class ESXi5xFDMSSLConfigUpdater
{
    private String vsphereIp;
    private String userName;
    private String password;
    private String esxUsername;
    private String esxPassword;
    private String hostsInfoFileLocation;
    private String url;
    private ServiceInstance si;

    // Supported VC & ESXi server release versions of 55 for SSL Toggling
    private final String SUPPORTED_55_VERSION = "5.5.0";
    private final Integer SUPPORTED_UPDATE_VER = 3; // Update 3 and above
    private final Integer SUPPORTED_VC_55_BUILD_NUMBER = 3252642; // VC GA build number of 5.5U3b/P07
    private final Integer SUPPORTED_ESX_55_BUILD_NUMBER = 3248547; // ESXi GA build number of 5.5U3b/P07
    private final String CMD_VERSION_CHECK = "esxcli system version get";

    // Security protocol strings
    private final String PROTO_SSLV3 = "sslv3";
    private final String PROTO_TLS10 = "tlsv1";
    private final String PROTO_TLS11 = "tlsv1.1";
    private final String PROTO_TLS12 = "tlsv1.2";

    // TLSv1.0 protocol as seen by TestSSLServer open source tool
    private final String TESTSSLSERVER_PROTO_TLS10 = "TLSv1.0";

    // SSH service
    private final String SSH_SERVICE = "TSM-SSH";
    private String SERVICE_RUNNING = "on";
    private String SERVICE_STOPPED = "off";
    private boolean cleanupStopSSHService = false;

    // VC inventory related objects
    public static final String DC_MOR_TYPE = "Datacenter";
    public static final String CLUSTER_COMPRES_MOR_TYPE = "ClusterComputeResource";
    public static final String VC_ROOT_TYPE = "VCRoot";
    public static final String HOST_MOR_TYPE = "HostSystem";
    public static final String VM_MOR_TYPE = "VirtualMachine";

    private String tls_protos_enable;
    private ArrayList<String> secProtosToEnable;
    private File existingFilePtr;
    private boolean cluAdvOpAdded;

    // FDM Values
    private final String HA_SSL_CONFIG_OPTION = "das.config.vmacore.ssl.sslOptions";

    /*
     * Protocols to Enable : Decimal val
     * sslv3, tls1, tls11, tls12: 16924672
     * tls1, tls11, tls12: 50479104
     */
    private String HA_SSL_OP_VAL;
    private final int FDM_PORT = 8182;
    private final String DEFAULT_ENABLE_SSLOP_VAL = "16924672";
    private final String DEFAULT_DISABLE_SSLOP_VAL = "50479104";

    // Map Port -> Service Name
    public final Map<Integer, String> portToServiceNameMap = new HashMap<Integer, String>() {
        {
            put(FDM_PORT, "vSphere HA");
        }
    };

    // Map <Hostname, TLS protocols in string>
    private Map<String, String> beforeTLSProtosOfCluHosts;
    private Map<String, String> afterTLSProtosOfCluHosts;

    private List<OverallResultHolderClass> listOfClustersResultObj;

    // Cluster, list of TLS Qualified Hosts
    private Map<ManagedEntity, List<HostSystem>> allClusterNHostsMap;

    // HostName, SSH Connection obj for host
    private List<HostSSHInfoClass> sslQualHostSSHInfo;

    // private boolean clusterHostsTLSPreExists;
    // <hostname>, <HostTLSConfigResultHolder - contains port, before & after TLS Sec proto information>
    private HashMap<String, HostSSLResultHolderClass> hostSSLconfigResultHolderObj;
    private boolean enableSsl;

    /**
     * Constructor
     */
    public ESXi5xFDMSSLConfigUpdater(String[] cmdProps)
    {
        makeProperties(cmdProps);
    }

    /**
     * Default constructor
     */
    public ESXi5xFDMSSLConfigUpdater()
    {
        // Placeholder
    }

    /**
     * Read properties from command line arguments
     */
    private void
    makeProperties(String[] cmdProps)
    {
        // get the property value and print it out
        System.out.println("Reading vSphere IP and Credentials information from command line arguments");
        System.out.println("-------------------------------------------------------------------");

        for (int i = 0; i < cmdProps.length; i++) {
            if (cmdProps[i].equals("--vsphereip")) {
                vsphereIp = cmdProps[i + 1];
                System.out.println("vSphere IP:" + vsphereIp);
            } else if (cmdProps[i].equals("--username")) {
                userName = cmdProps[i + 1];
                System.out.println("Username:" + userName);
            } else if (cmdProps[i].equals("--password")) {
                password = cmdProps[i + 1];
                System.out.println("password: ******");
            } else if (cmdProps[i].equals("--esxUsername")) {
                esxUsername = cmdProps[i + 1];
                System.out.println("ESX Username:" + esxUsername);
            } else if (cmdProps[i].equals("--esxPassword")) {
                esxPassword = cmdProps[i + 1];
                System.out.println("ESX password: ******");
            } else if (cmdProps[i].equals("--hostsinfofile")) {
                hostsInfoFileLocation = cmdProps[i + 1];
                System.out.println("Hosts information file:" + hostsInfoFileLocation);
            } else if (cmdProps[i].equals("enablessl")) {
                tls_protos_enable = PROTO_SSLV3 + "," + PROTO_TLS10 + "," + PROTO_TLS11 + "," + PROTO_TLS12;
                enableSsl = true;
                System.out.println("SSLv3 Protocol : Enable");
            } else if (cmdProps[i].equals("disablessl")) {
                tls_protos_enable = PROTO_TLS10 + "," + PROTO_TLS11 + "," + PROTO_TLS12;
                enableSsl = false;
                System.out.println("SSLv3 Protocol : Disable");
            }
        }
        System.out.println("-------------------------------------------------------------------\n");
    }

    /**
     * Validate property values
     */
    boolean
    validateProperties()
    {
        boolean val = false;

        if (vsphereIp != null) {
            url = "https://" + vsphereIp + "/sdk";

            // Login to provided server IP to determine if we are running against single ESXi
            try {
                System.out.println("Logging into vSphere : " + vsphereIp + ", with provided credentials");
                si = loginTovSphere(url);

                if (si != null) {
                    System.out.println("Succesfully logged into vSphere: " + vsphereIp);
                    val = true;
                } else {
                    System.err.println(
                        "Service Instance object for vSphere:" + vsphereIp + " is null, probably we failed to login");
                    printFailedLoginReasons();
                    val = false;
                }
            } catch (Exception e) {
                System.err.println(
                    "Caught an exception, while logging into vSphere :" + vsphereIp + " with provided credentials");
                printFailedLoginReasons();
                val = false;
            }

            if (val) {
                if (tls_protos_enable != null) {
                    this.secProtosToEnable = new ArrayList<String>();
                    if (enableSsl) {
                        this.secProtosToEnable.add(PROTO_SSLV3);
                        this.secProtosToEnable.add(PROTO_TLS10);
                        this.secProtosToEnable.add(PROTO_TLS11);
                        this.secProtosToEnable.add(PROTO_TLS12);
                        HA_SSL_OP_VAL = "16924672";
                        val = true;
                    } else {
                        this.secProtosToEnable.add(PROTO_TLS10);
                        this.secProtosToEnable.add(PROTO_TLS11);
                        this.secProtosToEnable.add(PROTO_TLS12);
                        HA_SSL_OP_VAL = "50479104";
                        val = true;
                    }
                } else {
                    System.err
                        .println("SSL Protocol to enable or disable property is null. See below the usage of script");
                    RunApp.usageSSLScript();
                    val = false;
                }

                /*
                 * Check if file consisting of ESXi hosts information is provided OR common ESXi username
                 * & password is provided, to be used for all ESXi hosts
                 */
                if (val) {
                    if (esxUsername == null && esxPassword == null) {
                        if (hostsInfoFileLocation != null) {
                            // FileHandling operation -- validate if provided file indeed exists
                            existingFilePtr = new File(hostsInfoFileLocation);
                            if (existingFilePtr.canRead()) {
                                System.out
                                    .println("Found the provided hosts information file: " + hostsInfoFileLocation);
                            } else {
                                System.err.println(
                                    "Could not find/read the provided hosts information file: "
                                        + hostsInfoFileLocation);
                                System.err.println("Please check if file really exists and is read'able");
                                val = false;
                            }
                        } else {
                            System.err.println(
                                "Hosts file information is not provided for applying TLS configurations. See below the usage of script");
                            RunApp.usageSSLScript();
                            val = false;
                        }
                    } else {
                        val = true;
                    }
                }
            }
        } else {
            System.err.println("vSphere IP is null. See below the usage of script");
            RunApp.usageSSLScript();
        }

        Scanner sc = new Scanner(System.in);
        try {
            // Alert customer if request is to 'Disable TLSv1.0' and allow to decide, if they would like to continue
            if (val && !enableSsl) {
                System.out
                    .println("\n * * * * * * * * * * * * * * * * *  W A R N I N G  * * * * * * * * * * * * * * * * * ");
                System.out.println(
                    "Disabling SSLv3 protocol might break VC/ESXi product interoperability and with"
                        + " Solutions that are on top of vSphere.\n"
                        + " Please refer to compatibility guide, before proceeding.\n");

                System.out.print("Would you like to continue? Please enter [Yes/No] ...: ");
                String readInput = sc.next();
                String proceed = "yes";
                if (proceed.equalsIgnoreCase(readInput)) {
                    System.out.println("\nContinuing the script execution ...");
                    val = true;
                } else {
                    System.out.println("\nEnding the script execution");
                    val = false;
                }
                sc.reset();
            }
        } catch (Exception e) {
            System.err.println("Error occurred while reading input. Please try again...");
            e.printStackTrace();
            val = false;
        } finally {
            sc.reset();
        }
        return val;
    }

    /**
     * Method prints out possible reasons for failed login
     */
    private void
    printFailedLoginReasons()
    {
        System.err.println(
            "Possible reasons:\n1. Provided username/password credentials are incorrect\n"
                + "2. If username/password or other fields contain special characters, surround them with double "
                + "quotes and for non-windows environment with single quotes (Refer readme doc for more information)\n"
                + "3. vCenter Server/ESXi server might not be reachable\n"
                + "4. vCenter Server service is configured with custom port (other than 443), If so specify vsphereip as \"serverip:customport\"");
    }

    /**
     * Check if vCenter Server and ESXi hosts are running supported versions for SSLv3 toggling
     */
    boolean
    validatevSphereVersion()
    {
        boolean runningSupportedVer = false;
        boolean sslConfigSupportedOnVC = false;

        try {
            System.out.println(
                "\n* * * * Checking if vCenter Server version is supported for SSLv3 configuration ... * * * *");
            /*
             * check vCenter Server version
             */
            String vcVersion = si.getAboutInfo().getVersion();
            Integer vcBuild = Integer.parseInt(si.getAboutInfo().getBuild());

            /*
             * Returns 0 : if current version == supported Version
             * Returns =<-1 (i.e. < 0): if current version is lower than supported version
             * Returns >=1 (i.e. > 0): if current version is higher than supported version
             */
            int isVerSupported = -1; // Not supported, to start off
            isVerSupported = compare(vcVersion, SUPPORTED_55_VERSION);

            if ((isVerSupported >= 0 && (vcBuild.compareTo(SUPPORTED_VC_55_BUILD_NUMBER) >= 0))) {
                System.out.println(
                    "This vCenter Server (" + vcVersion + ", " + "Build-" + vcBuild
                        + ") is supported for SSLv3 security protocols configuration");

                sslConfigSupportedOnVC = true;
            } else {
                System.out.println(
                    "This vCenter Server (" + vcVersion + ", " + "Build-" + vcBuild
                        + ") is NOT supported for SSLv3 security protocols configuration");
                System.err.println(
                    "SSLv3 Security protocol configuration is supported on versions " + "equal to or higher than : "
                        + SUPPORTED_55_VERSION + " Update-" + SUPPORTED_UPDATE_VER + " Build-"
                        + SUPPORTED_VC_55_BUILD_NUMBER);
                System.err.println(
                    "If your vCenter Server version/build number is higher, "
                        + "please check if its an HotPatch build, built on top of base "
                        + "ESXi release-where SSLv3 protocol configuration was not supported initially");
            }

            if (sslConfigSupportedOnVC) {
                // retrieve all HA Enabled Clusters and hosts
                System.out.println("\nRetrieve all HA enabled Clusters and ESXi hosts that are part of it ...");
                Map<ManagedEntity, List<HostSystem>> tempAllClusterNHostsMap = retrieveAllHAClustersNHosts();
                allClusterNHostsMap = new HashMap<ManagedEntity, List<HostSystem>>();

                if (tempAllClusterNHostsMap.size() > 0) {
                    System.out.println(
                        "\n* * * * Checking if ESXi Server version is supported for SSLv3 configuration ...* * * *");
                    sslQualHostSSHInfo = new ArrayList<HostSSHInfoClass>();

                    // Traverse through each cluster, and each host
                    for (ManagedEntity tempHaCluster : tempAllClusterNHostsMap.keySet()) {
                        System.out.println(
                            "\n ~~~~~~~~~~~~~~~~~~ Cluster : " + tempHaCluster.getName() + " ~~~~~~~~~~~~~~~~~~");
                        try {
                            List<HostSystem> currentClusterHosts = tempAllClusterNHostsMap.get(tempHaCluster);

                            if (esxUsername != null && esxPassword != null) {
                                List<HostSystem> sslQualifiedCluHosts = new ArrayList<>();

                                for (HostSystem tempHs : currentClusterHosts) {
                                    if (hostVerCheckerForSSLSupport(tempHs, esxUsername, esxPassword)) {
                                        sslQualifiedCluHosts.add(tempHs);
                                    } else {
                                        break;
                                    }
                                }

                                if (currentClusterHosts.size() == sslQualifiedCluHosts.size()) {
                                    allClusterNHostsMap.put(tempHaCluster, sslQualifiedCluHosts);
                                } else {
                                    System.err.println(
                                        "Not all hosts from the Cluster: " + tempHaCluster.getName()
                                            + " are running ESXi version"
                                            + "which is supported for SSLv3 configuration.");
                                    System.err.println(
                                        "Skipping cluster: " + tempHaCluster.getName() + " from SSLv3 configuration");
                                    cleanupHostSSHConnState();
                                }

                            } else {
                                List<HostInfoHelper.HostsInfoHolderClass> hostsListFromFile = readHostsInfoFromFile(
                                    currentClusterHosts);
                                if (hostsListFromFile != null && hostsListFromFile.size() > 0) {
                                    if (hostsListFromFile.size() == currentClusterHosts.size()) {
                                        List<HostSystem> sslQualifiedCluHosts = new ArrayList<>();

                                        for (HostInfoHelper.HostsInfoHolderClass hostInfoObj : hostsListFromFile) {
                                            if (hostVerCheckerForSSLSupport(
                                                hostInfoObj.hostSys,
                                                hostInfoObj.username,
                                                hostInfoObj.password)) {
                                                sslQualifiedCluHosts.add(hostInfoObj.hostSys);
                                            } else {
                                                break;
                                            }
                                        }

                                        if (currentClusterHosts.size() == sslQualifiedCluHosts.size()) {
                                            allClusterNHostsMap.put(tempHaCluster, sslQualifiedCluHosts);
                                        } else {
                                            System.err.println(
                                                "Not all hosts from the Cluster: " + tempHaCluster.getName()
                                                    + " are running ESXi version"
                                                    + "which is supported for SSLv3 configuration.");
                                            System.err.println(
                                                "Skipping cluster: " + tempHaCluster.getName()
                                                    + " from SSLv3 configuration");
                                            cleanupHostSSHConnState();
                                        }
                                    } else {
                                        System.err.println("Current active Hosts count from Cluster: "
                                            + tempHaCluster.getName() + " and Hosts count from HostInfoFile: "
                                            + hostsInfoFileLocation + " does not match.");
                                        System.err.println(
                                            "Skipping cluster: " + tempHaCluster.getName()
                                                + " from SSLv3 configuration");
                                    }
                                } else {
                                    System.err.println(
                                        "The hosts specified in HostInfoFile: " + hostsInfoFileLocation
                                            + " does not belong to cluster: " + tempHaCluster.getName());
                                    System.err.println("Skipping cluster: " + tempHaCluster.getName());
                                }
                            }

                        } catch (Exception e) {
                            System.err.println(
                                "Caught exception while validating Clustered ESXi hosts version check for SSLv3 toggling");
                            cleanupHostSSHConnState();
                        }
                    } // End of cluster loop
                }
            }

        } catch (Exception e) {
            System.err.println("Caught exception while validating vSphere version check for SSLv3 toggling");
        }

        if (allClusterNHostsMap != null && allClusterNHostsMap.size() > 0) {
            runningSupportedVer = true;
        }

        return runningSupportedVer;
    }

    /**
     * Restore SSH Service state on host and close the SSH connection
     */
    private void
    cleanupHostSSHConnState()
    {
        if (sslQualHostSSHInfo != null) {
            for (HostSSHInfoClass hostSshInfoObj : sslQualHostSSHInfo) {
                try {
                    if (hostSshInfoObj.restoreSSHServiceState) {
                        System.out.println("[" + hostSshInfoObj.hostName + "] Restore SSH service state ...");
                        if (stopSSHService(hostSshInfoObj.hostSys)) {
                            System.out
                                .println("[" + hostSshInfoObj.hostName + "] Successfully reverted SSH service state");
                        } else {
                            System.out.println(
                                "[" + hostSshInfoObj.hostName + "] [ALERT] Failed to revert SSH Service state");
                        }
                        if (hostSshInfoObj.hostSshConnObj != null) {
                            hostSshInfoObj.hostSshConnObj.close();
                        }
                    }
                } catch (Exception e) {
                    System.err.println(
                        "[" + hostSshInfoObj.hostName + "] Caught exception while cleaning up SSH related information");
                }
            }
        }

        sslQualHostSSHInfo = null;
    }

    /**
     * Read hosts information from file
     */
    private List<HostInfoHelper.HostsInfoHolderClass>
    readHostsInfoFromFile(List<HostSystem> clusteredHosts)
    {
        List<HostInfoHelper.HostsInfoHolderClass> hostsInfo = new ArrayList<HostInfoHelper.HostsInfoHolderClass>();

        List<HostInfoHelper.HostsInfoHolderClass> tempAllHostsListFromFile = HostInfoHelper
            .readHostsInfoFile(existingFilePtr);
        if (tempAllHostsListFromFile != null && tempAllHostsListFromFile.size() > 0) {
            hostsInfo = new ArrayList<HostInfoHelper.HostsInfoHolderClass>();
            for (HostInfoHelper.HostsInfoHolderClass tempHostInfo : tempAllHostsListFromFile) {

                for (HostSystem tempCluHostSys : clusteredHosts) {
                    if (tempCluHostSys.getName().equals(tempHostInfo.hostName)) {
                        System.out.println(
                            "[" + tempHostInfo.hostName + "] check if ESXi host exist & connected in VC inventory ...");
                        HostSystem tempHostSysFrmFile = retrieveSingleHostSys(tempHostInfo.hostName);
                        if (tempHostSysFrmFile != null) {
                            tempHostInfo.hostSys = tempCluHostSys;
                            hostsInfo.add(tempHostInfo);
                        } else {
                            System.out.println(
                                "Skipping ESXi host: " + tempHostInfo.hostName
                                    + ", as NOW; Either it is not in connected state Or it does not exist in inventory");
                        }
                    }
                }
            }
        }
        return hostsInfo;
    }

    /**
     * Return hosts reference
     */
    private HostSystem
    retrieveSingleHostSys(String hostName)
    {
        HostSystem hostSys = null;

        // get first datacenters in the environment.
        InventoryNavigator navigator = new InventoryNavigator(si.getRootFolder());

        try {
            hostSys = (HostSystem) navigator.searchManagedEntity(HOST_MOR_TYPE, hostName);
        } catch (Exception e) {
            System.err.println("Unable to retrieve provided Host's HostSystem object from inventory");
        }
        return hostSys;
    }

    /**
     * Check ESXi hosts version to determine if SSLv3 configuration is supported or not
     * SSLv3 Configuration support starts from 5.5U3b/P07 release and onwards
     */
    private boolean
    hostVerCheckerForSSLSupport(HostSystem hostSys, String esxUserName, String esxPasswd)
    {
        String esxi_version = null;
        Integer esxi_build = null;
        Integer esxi_update = null;
        boolean sslConfigSupported = false;
        String supportedVersion = null;
        Integer supportedUpdateVersion = null;
        Integer supportedBuildNumber = null;
        Connection hostSshConnObj = null;
        String hostName = hostSys.getName();
        HostSSHInfoClass hostSSHInfoObj = new HostSSHInfoClass();

        try {
            System.out.println(
                "[" + hostName + "] Try to start SSH Service, if its not started already. "
                    + "This is needed to establish SSH Connection with ESXi host");

            if (startSSHService(hostSys)) {
                // restore the flag state
                boolean restoreSSHServiceState = cleanupStopSSHService;
                cleanupStopSSHService = false;

                // populate the SSLv3 compatible host info first
                hostSSHInfoObj.hostName = hostName;
                hostSSHInfoObj.hostSys = hostSys;
                hostSSHInfoObj.restoreSSHServiceState = restoreSSHServiceState;

                hostSshConnObj = SSHUtil.getSSHConnection(hostSys.getName(), esxUserName, esxPasswd);

                if (hostSshConnObj != null) {
                    hostSSHInfoObj.hostSshConnObj = hostSshConnObj;

                    String verCmdoutput = SSHUtil.getSSHOutputStream(hostSshConnObj, CMD_VERSION_CHECK);

                    if (verCmdoutput != "" || verCmdoutput != null) {
                        String[] fullVersionString = verCmdoutput.split("\n");
                        for (String tempfullVerString : fullVersionString) {
                            String productInfo = tempfullVerString.replaceAll("( )+", "").trim().toLowerCase();
                            if (productInfo.contains("version")) {
                                esxi_version = productInfo.split(":")[1];
                                if (esxi_version.contains(SUPPORTED_55_VERSION)) {
                                    supportedVersion = SUPPORTED_55_VERSION;
                                    supportedUpdateVersion = SUPPORTED_UPDATE_VER;
                                    supportedBuildNumber = SUPPORTED_ESX_55_BUILD_NUMBER;
                                }
                            } else if (productInfo.contains("build")) {
                                esxi_build = Integer.parseInt(productInfo.split(":")[1].replace("releasebuild-", ""));
                            } else if (productInfo.contains("update")) {
                                esxi_update = Integer.parseInt(productInfo.split(":")[1]);
                            }
                        }
                    }
                    /*
                     * Returns 0 : if current version == supported Version
                     * Returns =<-1 (i.e. < 0): if current version is lower than supported version
                     * Returns >=1 (i.e. > 0): if current version is higher than supported version
                     */
                    int isVerSupported = -1; // Not supported, to start off
                    if (supportedVersion != null) {
                        isVerSupported = compare(esxi_version, supportedVersion);
                    }
                    if ((isVerSupported >= 0 && (esxi_update.compareTo(supportedUpdateVersion) >= 0)
                        && (esxi_build.compareTo(supportedBuildNumber) >= 0))) {
                        // Version check done - supported version of ESXi for SSLv3 toggling
                        System.out.println(
                            "[" + hostName + "] This ESXi host (" + esxi_version + ", Update-" + esxi_update + " Build-"
                                + esxi_build + ") is supported for SSLv3 security protocols configuration");
                        sslConfigSupported = true;
                    } else {
                        System.err.println(
                            "[" + hostName + "] This ESXi host (" + esxi_version + ", Update-" + esxi_update + " Build-"
                                + esxi_build + ") is NOT supported for SSLv3 security protocols configuration");
                        if (supportedVersion != null) {
                            System.err.println(
                                "[" + hostName + "] SSLv3 Security protocol configuration is supported on versions "
                                    + "equal to or higher than : " + supportedVersion + " Update-"
                                    + supportedUpdateVersion + " Build-" + supportedBuildNumber);
                        } else {
                            System.err.println(
                                "[" + hostName
                                    + "] SSLv3 Security protocol configuration is supported on release : 5.5P08, 6.0U2 and onwards");
                        }
                        System.err.println(
                            "[" + hostName + "] If your ESXi hosts version/build number is higher, "
                                + "please check if its an HotPatch build, built on top of base "
                                + "ESXi release-where SSLv3 protocol configuration was not supported initially");
                    }
                } else {
                    System.err.println("[" + hostName + "] Could not establish SSH connection with host");
                }

            } else {
                System.err.println("[" + hostName + "] Could not start SSH service on host, which is a must");
            }

        } catch (Exception e) {
            System.err.println("Caught exception while determining SSLv3 Configuration support for ESXi hosts");
            e.printStackTrace();
        }

        sslQualHostSSHInfo.add(hostSSHInfoObj);
        return sslConfigSupported;
    }


    /**
     * Compare version strings * Returns 0 : if current version == supported
     * Version Returns =<-1 (i.e. < 0): if current version is lower than
     * supported version Returns >=1 (i.e. > 0): if current version is higher
     * than supported version
     */
    private int
    compare(String currVer, String supportedVer)
    {
        currVer = normalizedVersion(currVer);
        supportedVer = normalizedVersion(supportedVer);
        int cmp = currVer.compareTo(supportedVer);
        return cmp;
    }

    /**
     * Normalize the strings passed from Compare method
     */
    private String
    normalizedVersion(String version)
    {
        String separator = ".";
        int maxWidth = 3;
        String[] split = Pattern.compile(separator, Pattern.LITERAL).split(version);
        StringBuilder sb = new StringBuilder();
        for (String s : split) {
            sb.append(String.format("%" + maxWidth + 's', s));
        }
        return sb.toString();
    }

    /**
     * Start SSH Services
     */
    private boolean
    startSSHService(HostSystem hostSys)
    {
        boolean startedService = false;

        try {
            HostServiceSystem hss = hostSys.getHostServiceSystem();
            for (HostService tempHs : hss.getServiceInfo().getService()) {
                String id = tempHs.getKey();
                if (SSH_SERVICE.equalsIgnoreCase(id)) {
                    if (!(getServiceState(hostSys, id).equalsIgnoreCase(SERVICE_RUNNING))) {
                        hss.startService(id);

                        // Check if we indeed were successful in starting services
                        if (getServiceState(hostSys, id).equalsIgnoreCase(SERVICE_RUNNING)) {
                            System.out.println(SSH_SERVICE + " service is in running state now");
                            startedService = true;

                            // below flag is for cleanup purpose - restoring
                            // previous state
                            cleanupStopSSHService = true;
                            break;
                        } else {
                            System.err.println(SSH_SERVICE + " service could not be started");
                            break;
                        }
                    } else {
                        System.out.println(SSH_SERVICE + " service is already in running state");
                        startedService = true;
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Caught exception while starting SSH service");
        }

        return startedService;
    }

    /**
     * Stop SSH Services
     */
    private boolean
    stopSSHService(HostSystem hostSys)
    {
        boolean stoppedService = false;

        try {
            HostServiceSystem hss = hostSys.getHostServiceSystem();
            for (HostService tempHs : hss.getServiceInfo().getService()) {
                String id = tempHs.getKey();
                if (SSH_SERVICE.equalsIgnoreCase(id)) {
                    if (!(getServiceState(hostSys, id).equalsIgnoreCase(SERVICE_STOPPED))) {
                        hss.stopService(id);

                        // Check if we indeed were successful in stopping services
                        if (getServiceState(hostSys, id).equalsIgnoreCase(SERVICE_STOPPED)) {
                            System.out.println(SSH_SERVICE + " service is stopped now");
                            stoppedService = true;
                            break;
                        } else {
                            System.err.println(SSH_SERVICE + " service could not be stopped");
                            break;
                        }
                    } else {
                        System.out.println(SSH_SERVICE + " service is already stopped");
                        stoppedService = true;
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Caught exception while turning off SSH service");
        }

        return stoppedService;
    }

    /**
     * Get ServiceState
     */
    private String
    getServiceState(HostSystem hs, String id) throws Exception
    {
        String serviceState = null;

        HostServiceSystem hss = hs.getHostServiceSystem();
        for (HostService tempHsService : hss.getServiceInfo().getService()) {
            if (id.equalsIgnoreCase(tempHsService.getKey())) {
                if (tempHsService.isRunning()) {
                    serviceState = SERVICE_RUNNING;
                } else {
                    serviceState = SERVICE_STOPPED;
                }
            }
        }

        return serviceState;
    }

    /**
     * Check and apply SSLv3 protocol configuration on HA Enabled Clusters
     */
    void
    applySSLConfigOnClusters()
    {
        System.out.println("\n* * * * Apply SSLv3 configuration changes on Clusters ...* * * *");
        listOfClustersResultObj = new ArrayList<OverallResultHolderClass>();

        // For each Cluster, apply the changes
        for (ManagedEntity tempHaCluster : allClusterNHostsMap.keySet()) {
            boolean clusterConfigSuccess = false;

            ClusterInfoClassForRestore copyOfOriClusterInfoObj = new ClusterInfoClassForRestore();
            ClusterInfoClassForRestore oriClusterInfoObj = new ClusterInfoClassForRestore();
            List<HostSystem> clusteredHosts = allClusterNHostsMap.get(tempHaCluster);
            OverallResultHolderClass clusterResultHolderObj = new OverallResultHolderClass();

            try {
                System.out.println("\n******************************************************************************");
                System.out.println("\t\t\t CLUSTER : " + tempHaCluster.getName());
                System.out.println("******************************************************************************");
                Thread.sleep(500);

                /*
                 * Check if required version of SSLv3 protocols are already running on the port
                 */
                beforeTLSProtosOfCluHosts = new HashMap<String, String>();

                System.out.println("Check if requested protocols are enabled on clustered hosts ... ");
                Boolean userReqdProtosRunning = null;
                try {
                    userReqdProtosRunning = checkSSLProtocols(clusteredHosts, true);
                } catch (Exception e) {
                    userReqdProtosRunning = null;
                }

                // if (!checkSSLProtocols(clusteredHosts, true)) {
                if (userReqdProtosRunning != null) {
                    if (!userReqdProtosRunning) {
                        System.out
                            .println("Clustered Hosts yet to be configured with required version of SSLv3 protocol");

                        ClusterComputeResource haCcr = new ClusterComputeResource(si.getServerConnection(),
                            tempHaCluster.getMOR());
                        oriClusterInfoObj.cluster = tempHaCluster;
                        oriClusterInfoObj.hosts = clusteredHosts;
                        oriClusterInfoObj.clusterConfigInfo = (ClusterConfigInfoEx) haCcr.getConfigurationEx();
                        oriClusterInfoObj.ccr = haCcr;

                        // Take a copy of the original configuration, as a backup
                        copyOfOriClusterInfoObj.cluster = tempHaCluster;
                        copyOfOriClusterInfoObj.hosts = clusteredHosts;
                        copyOfOriClusterInfoObj.clusterConfigInfo = (ClusterConfigInfoEx) haCcr.getConfigurationEx();
                        copyOfOriClusterInfoObj.ccr = haCcr;

                        /*
                         * Apply the SSLv3 protocol configuration on Cluster and reconfigure HA on all clustered hosts
                         */
                        if (updateClusterWithSSLProtocols(oriClusterInfoObj)) {
                            System.out.println("Updated the cluster with advanced option and reconfigured HA on hosts");

                            // Check if we were indeed successful in rolling out the changes
                            afterTLSProtosOfCluHosts = new HashMap<String, String>();
                            if (verifySSLProtoPostReconfig(clusteredHosts, this.secProtosToEnable)) {
                                System.out
                                    .println("Succesfully enabled requested SSLv3 protocol on all clustered hosts");
                                clusterConfigSuccess = true;

                                // populate the result holder object and class
                                clusterResultHolderObj.cluName = tempHaCluster.getName();
                                clusterResultHolderObj.beforeTLSProtos = beforeTLSProtosOfCluHosts;
                                clusterResultHolderObj.afterTLSProtos = afterTLSProtosOfCluHosts;
                                listOfClustersResultObj.add(clusterResultHolderObj);
                            } else {
                                System.err.println("Failed to enable requested SSLv3 protocol on all clustered hosts");
                            }
                        }
                    } else {
                        System.out
                            .println("Clustered Hosts are already configured with required version of SSLv3 protocols");
                        clusterConfigSuccess = true;
                        // populate the result holder object and class
                        clusterResultHolderObj.cluName = tempHaCluster.getName();
                        clusterResultHolderObj.beforeTLSProtos = beforeTLSProtosOfCluHosts;

                        afterTLSProtosOfCluHosts = new HashMap<String, String>();
                        afterTLSProtosOfCluHosts.putAll(beforeTLSProtosOfCluHosts);
                        clusterResultHolderObj.afterTLSProtos = afterTLSProtosOfCluHosts;
                        listOfClustersResultObj.add(clusterResultHolderObj);
                    }
                }

            } catch (Exception e) {
                System.err.println("[AllClustersLoop] Caught exception while applying the changes on a cluster");
                restoreClusterConfiguration(copyOfOriClusterInfoObj);
            }

            try {
                if (!clusterConfigSuccess) {
                    restoreClusterConfiguration(copyOfOriClusterInfoObj);
                }

                // Print the cluster config result
                if (listOfClustersResultObj != null && listOfClustersResultObj.size() > 0) {
                    printSSLConfigResult(false, tempHaCluster.getName());
                }
            } finally {
                cluAdvOpAdded = false;
                beforeTLSProtosOfCluHosts = null;
                afterTLSProtosOfCluHosts = null;
            }

        } // End of Clusters - for loop

        if (listOfClustersResultObj != null && listOfClustersResultObj.size() > 0) {
            // Print overall result
            printSSLConfigResult(true, null);

            // And print the result into file
            try {
                if (hostSSLconfigResultHolderObj != null && hostSSLconfigResultHolderObj.size() > 0) {
                    HostInfoHelper.createHostSSLConfigResultFile(hostSSLconfigResultHolderObj, tls_protos_enable);
                }
            } catch (IOException e) {
                System.err.println("Caught an exception while writing SSL Configuration result into file");
                e.printStackTrace();
            }
        }

        // restore SSH Service State
        try {
            cleanupHostSSHConnState();
        } catch (Exception e) {
            System.err.println(
                "Caught exception while restoring SSH Service state of ESXi hosts, Pls check and revert the state manually");
        }
    }

    /**
     * Print SSL Configuration result of provided or all hosts
     */
    private void
    printSSLConfigResult(boolean overallResult, String clusterName)
    {
        try {
            if (listOfClustersResultObj != null && listOfClustersResultObj.size() > 0) {
                if (overallResult) {
                    hostSSLconfigResultHolderObj = new HashMap<String, HostSSLResultHolderClass>();

                    System.out
                        .println("@@@@@@@@@@@@@@@@@ ALL CLUSTERED HOSTS SSL CONFIGURATION RESULT @@@@@@@@@@@@@@@@@");
                    for (OverallResultHolderClass tempCluResObj : listOfClustersResultObj) {
                        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                        System.out.println(" SSL CONFIGURATION RESULT FOR CLUSTER: " + tempCluResObj.cluName);
                        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                        System.out.println("Protocols to ENABLE (as requested by user) : " + tls_protos_enable + "\n");

                        ResultTablePrinter resultObj = new ResultTablePrinter();
                        resultObj.addLine("------------", "----", "--------------------", "-------------------");
                        resultObj
                            .addLine("HOST NAME   ", "PORT", "Before SSL/TLS Protocols", "After SSL/TLS Protocols");
                        resultObj.addLine("------------", "----", "--------------------", "-------------------");

                        for (String hostName : tempCluResObj.beforeTLSProtos.keySet()) {
                            String beforeProtos = tempCluResObj.beforeTLSProtos.get(hostName);
                            String afterProtos = null;

                            if (tempCluResObj.afterTLSProtos.containsKey(hostName)) {
                                afterProtos = tempCluResObj.afterTLSProtos.get(hostName);
                            }

                            if (afterProtos == null) {
                                afterProtos = "NULL (Pls check manually)";
                            }
                            resultObj.addLine(hostName, String.valueOf(FDM_PORT), beforeProtos, afterProtos);

                            // add in class object for creating file with all this information
                            HostSSLResultHolderClass tlsResClassObj = new HostSSLResultHolderClass();
                            tlsResClassObj.port = FDM_PORT;
                            tlsResClassObj.beforeProtoList = beforeProtos;
                            tlsResClassObj.afterProtoList = afterProtos;
                            tlsResClassObj.clusterName = tempCluResObj.cluName;
                            hostSSLconfigResultHolderObj.put(hostName, tlsResClassObj);

                        }
                        resultObj.addLine("------------", "----", "--------------------", "-------------------");
                        resultObj.print();
                    }
                } else {
                    System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    System.out.println(" SSL CONFIGURATION RESULT FOR CLUSTER: " + clusterName);
                    System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    System.out.println("Protocols to ENABLE (as requested by user) : " + tls_protos_enable + "\n");

                    ResultTablePrinter resultObj = new ResultTablePrinter();
                    resultObj.addLine("------------", "----", "--------------------", "-------------------");
                    resultObj.addLine("HOST NAME   ", "PORT", "Before SSL/TLS Protocols", "After SSL/TLS Protocols");
                    resultObj.addLine("------------", "----", "--------------------", "-------------------");

                    for (OverallResultHolderClass tempAllCluResObj : listOfClustersResultObj) {
                        if (tempAllCluResObj.cluName.equals(clusterName)) {
                            for (String hostName : tempAllCluResObj.beforeTLSProtos.keySet()) {
                                String beforeProtos = tempAllCluResObj.beforeTLSProtos.get(hostName);
                                String afterProtos = null;

                                if (tempAllCluResObj.afterTLSProtos.containsKey(hostName)) {
                                    afterProtos = tempAllCluResObj.afterTLSProtos.get(hostName);
                                }

                                if (afterProtos == null) {
                                    afterProtos = "NULL (Pls check manually)";
                                }
                                resultObj.addLine(hostName, String.valueOf(FDM_PORT), beforeProtos, afterProtos);

                            }
                        }
                    }
                    resultObj.addLine("------------", "----", "--------------------", "-------------------");
                    resultObj.print();
                }
            } else {
                System.err.println("[ALERT] Before and After Protocol Result Maps are Null!");
                System.err.println("[ALERT] Pls check the logs and inventory");
            }

        } catch (Exception e) {
            System.err.println("[ALERT] Caught an exception, while printing out SSL Configuration result");
            System.err.println("[ALERT] Pls check the logs and inventory");
        }
    }

    /**
     * Restore Cluster settings (as it was before start of the test) and reconfigure HA on hosts
     */
    private void
    restoreClusterConfiguration(ClusterInfoClassForRestore oriClusterInfoObj)
    {
        if (oriClusterInfoObj.cluster != null) {
            String cluName = oriClusterInfoObj.cluster.getName();
            System.out.println("\n* * * * * * * * RESTORE SETTINGS ON CLUSTER : " + cluName + " * * * * * * * *");

            try {
                if (cluAdvOpAdded) {
                    System.out.println("SSL Advanced option was added to cluster, revert the change ...");
                    if (removeClusterAdvOption(oriClusterInfoObj.ccr, oriClusterInfoObj.clusterConfigInfo)) {
                        // Reconfigure HA on Host, for the cluster related changes to take effect
                        Map<Boolean, List<HostSystem>> reconfigHostsResultMap = reconfigureHAOnCluHosts(
                            oriClusterInfoObj.hosts);

                        if (reconfigHostsResultMap.keySet().contains(Boolean.TRUE)) {
                            System.out.println("Reconfigure HA on ALL clustered hosts completed");
                        } else {
                            System.err.println(
                                "[ALERT] Reconfigure HA on clustered hosts failed. Pls check and reconfigure hosts manually");
                        }
                    } else {
                        System.err.println(
                            "[ALERT] Failed to restore Cluster settings. Pls check and revert the change manually");
                    }
                }
            } catch (Exception e) {
                System.err.println("[ALERT] Caught exception while restoring settings on Cluster: " + cluName);
                System.err.println("[ALERT] Pls check and revert the change manually");
            }

            List<HostSystem> cluHosts = oriClusterInfoObj.hosts;
            String[] protosToRevertStrArr = beforeTLSProtosOfCluHosts.get(cluHosts.get(0).getName())
                .replaceAll("[\\[\\]]", "").split(",");
            List<String> protosToRevert = new ArrayList<String>();
            for (String tempProto : protosToRevertStrArr) {
                protosToRevert.add(tempProto.trim());
            }

            verifySSLProtoPostReconfig(oriClusterInfoObj.hosts, protosToRevert);
            OverallResultHolderClass clusterResultHolderObj = new OverallResultHolderClass();
            // populate the result holder object and class
            clusterResultHolderObj.cluName = oriClusterInfoObj.cluster.getName();
            clusterResultHolderObj.beforeTLSProtos = beforeTLSProtosOfCluHosts;
            clusterResultHolderObj.afterTLSProtos = afterTLSProtosOfCluHosts;
            listOfClustersResultObj.add(clusterResultHolderObj);
        } else {
            System.out.println(
                "There is nothing to cleanup, as Cluster information is null. Probably we did not configure anything at all on Cluster");
        }
    }

    /**
     * Security Protocol Scanner
     */
    private List<String> securityProtocolScanner(String host, int port) {
        List<String> secProtocolList = null;

        try {
            List<String> tempSecProtoList = TestSSLServer.SecurityProtoScanner(host, port);

            /*
             * Convert the strings according to ESXi side implementation of
             * protocol strings All protocols are in small cases AND TSLv1.0 is
             * used as "tlsv1"
             */
            secProtocolList = new ArrayList<String>();
            for (String tempProtocol : tempSecProtoList) {
                if (tempProtocol.equals(TESTSSLSERVER_PROTO_TLS10)) {
                    secProtocolList.add(PROTO_TLS10);
                } else {
                    secProtocolList.add(tempProtocol.toLowerCase());
                }
            }
        } catch (Exception e) {
            System.err.println("[TestSSLServer Scanner] Caught exception while running scanner: " + e.getMessage());
        }

        return secProtocolList;
    }

    /**
     * Check if port is already running with user requested security protocols
     */
    private Boolean
    secProtoChecker(List<String> currList, List<String> expList)
    {
        Boolean areListsEqual = null;
        if (currList != null && currList.size() > 0) {
            areListsEqual = false;
            if (currList.containsAll(expList) && currList.size() == expList.size()) {
                System.out.println("Requested security protocol(s) is/are already enabled");
                areListsEqual = true;
            } else {
                System.out.println("Requested security protocol(s) needs to be enabled");
            }
        }
        return areListsEqual;
    }

    /**
     * Security protocol list validator - before and after modification
     * validates for number of elements and values.
     */
    private boolean
    secProtoListPostValidater(List<String> expList, List<String> afterChange) throws InterruptedException
    {
        boolean areListsEqual = false;

        if (afterChange != null && afterChange.size() > 0) {
            if (afterChange.size() == (expList.size())) {
                System.out
                    .println("Count of Protocol enabled list (" + "after updation of config file) is as expected");
                for (String tempSecProto : afterChange) {
                    if (expList.contains(tempSecProto)) {
                        System.out.println("Security protocol: \"" + tempSecProto + "\" found enabled");
                        areListsEqual = true;
                    } else {
                        System.err.println(
                            "Found unexpected Security protocol: \"" + tempSecProto
                                + "\" in the list after updation of config file");
                        areListsEqual = false;
                        break;
                    }
                }
            } else {
                System.err.println(
                    "Number of elements in the protocol enabled list "
                        + "(after updation of config file) is not as expected");
                Thread.sleep(100);
                System.out.println(" -------- ACTUAL -------");
                System.out.println(expList.toString());
                System.out.println(" -------- EXPECTED -------");
                System.out.println(afterChange.toString());
                areListsEqual = false;
            }
        } else {
            System.err.println("Security Protocols list either before/After change is null");
        }
        return areListsEqual;
    }

    /**
     * Login method to VC/ESXi
     */
    private ServiceInstance
    loginTovSphere(String url)
    {
        try {
            si = new ServiceInstance(new URL(url), userName, password, true);
        } catch (Exception e) {
            System.out.println("Caught exception while logging into vSphere server");
            e.printStackTrace();
        }
        return si;
    }

    /**
     * All hosts from HA Enabled Cluster
     */
    private Map<ManagedEntity, List<HostSystem>>
    retrieveAllHAClustersNHosts()
    {
        Map<ManagedEntity, List<HostSystem>> allClusHostsMap = new HashMap<ManagedEntity, List<HostSystem>>();

        try {
            InventoryNavigator navigator = new InventoryNavigator(si.getRootFolder());

            ManagedEntity[] allClusters = navigator.searchManagedEntities(CLUSTER_COMPRES_MOR_TYPE);

            if (allClusters.length > 0) {
                System.out.println("Found Clusters in inventory. Check and retrieve HA Enabled Cluster");

                /*
                 * Traverse through each Cluster
                 */
                for (ManagedEntity tempCluME : allClusters) {
                    ClusterComputeResource ccr = new ClusterComputeResource(si.getServerConnection(),
                        tempCluME.getMOR());

                    // Check if HA is enabled on Cluster
                    ClusterConfigInfo tempCluConfigInfo = ccr.getConfiguration();
                    ClusterDasConfigInfo fdmConfigInfo = tempCluConfigInfo.getDasConfig();

                    if (fdmConfigInfo != null && fdmConfigInfo.enabled) {
                        System.out.println("\nHA is enabled on Cluster: " + tempCluME.getName());

                        // retrieve all hosts from the cluster
                        System.out.println("Retrieve all ESXi hosts from Cluster: " + tempCluME.getName());
                        HostSystem[] allHosts = ccr.getHosts();
                        if (allHosts.length > 0) {
                            System.out.println("Found ESXi host(s). Check for all connected hosts");
                            List<HostSystem> activeHosts = new ArrayList<HostSystem>();
                            for (ManagedEntity tempHost : allHosts) {
                                HostSystem tempHostSys = (HostSystem) tempHost;
                                HostRuntimeInfo hostruntimeInfo = tempHostSys.getRuntime();
                                if ((hostruntimeInfo.getConnectionState()
                                    .equals(HostSystemConnectionState.connected))) {
                                    System.out
                                        .println("Found ESXi host: " + tempHostSys.getName() + " in connected state");
                                    activeHosts.add(tempHostSys);
                                }
                            }
                            if (activeHosts.size() > 0) {
                                allClusHostsMap.put(tempCluME, activeHosts);
                            } else {
                                System.out.println(
                                    "Could not find any ESXi host in connected state, for this cluster: "
                                        + tempCluME.getName());
                            }
                        }
                    } else {
                        System.out.println(
                            "\nHA is NOT enabled on Cluster: " + tempCluME.getName() + ", Hence skipping this cluster");
                    }
                }

                if (!(allClusHostsMap.size() > 0)) {
                    System.err.println("Could not find HA Enabled Cluster");
                }
            }

        } catch (Exception e) {
            System.err.println("[Error] Unable to retrieve Clusters from inventory");
            e.printStackTrace();
        }

        return allClusHostsMap;
    }

    /**
     * Check if requested version of SSL protocols are already enabled and running of FDM Port
     *
     * @throws Exception
     */
    private boolean
    checkSSLProtocols(List<HostSystem> hosts, boolean beforeConfig) throws Exception
    {
        int hostsNeedReconfigCounter = 0;
        int hostsAlreadyConfiguredCounter = 0;

        for (HostSystem tempHost : hosts) {
            try {
                System.out.println("[" + tempHost.getName() + "] Running protocol scanner on host");
                List<String> currProtos = securityProtocolScanner(tempHost.getName(), FDM_PORT);
                beforeTLSProtosOfCluHosts.put(tempHost.getName(), currProtos.toString());

                if (!this.secProtoChecker(currProtos, this.secProtosToEnable)) {
                    System.out.println("[" + tempHost.getName() + "] Requested protocols NEED to be enabled");
                    ++hostsNeedReconfigCounter;
                } else {
                    System.out.println("[" + tempHost.getName() + "] Requested protocols are already enabled");
                    ++hostsAlreadyConfiguredCounter;
                }
                System.out.println(
                    "[" + tempHost.getName() + "] List of security protocols currenty enabled (BEFORE CHANGE): "
                        + currProtos.toString());
            } catch (Exception e) {
                System.err.println("[" + tempHost.getName() + "] Caught Exception while scanning for SSL protocols");
                break;
            }
        }

        if (hostsAlreadyConfiguredCounter == hosts.size()) {
            // ALL hosts in cluster are already running with requested protocols
            return true;
        } else if (hostsNeedReconfigCounter == hosts.size()) {
            // ALL hosts in cluster yet to be enabled with requested protocols
            return false;
        } else {
            System.err.println(
                "NOT all hosts in Cluster needs reconfiguration. Indicates that there is NO security protocol consistency"
                    + " with all Clustered ESXi hosts");
            throw new Exception();
        }
    }

    /**
     * Check if SSL protocols are found enabled on FDM Port, after cluster/host reconfigured
     */
    private boolean
    verifySSLProtoPostReconfig(List<HostSystem> hosts, List<String> protosToEnable)
    {
        Boolean reqdProtosRunning = null;
        int hostsConfFailureCounter = 0;

        for (HostSystem tempHost : hosts) {
            try {
                System.out.println(
                    "[" + tempHost.getName() + "] Perform Post validation to check if"
                        + " user expected protocols are indeed persisted ...");
                List<String> currProtos = securityProtocolScanner(tempHost.getName(), FDM_PORT);
                afterTLSProtosOfCluHosts.put(tempHost.getName(), currProtos.toString());
                if (this.secProtoListPostValidater(currProtos, protosToEnable)) {
                    System.out.println(
                        "[" + tempHost.getName() + "] List of security protocols currenty enabled (AFTER CHANGE): "
                            + currProtos.toString());
                } else {
                    ++hostsConfFailureCounter;
                }
            } catch (Exception e) {
                System.err.println(
                    "[" + tempHost.getName()
                        + "] Caught Exception while scanning for existing SSL versions on Clustered host: "
                        + tempHost.getName());
                reqdProtosRunning = Boolean.FALSE;
            }
        }

        if (hostsConfFailureCounter > 0 || (reqdProtosRunning != null && reqdProtosRunning.equals(Boolean.FALSE))) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Add advanced option to disable/enable SSL protocol
     */
    private boolean
    updateClusterWithSSLProtocols(ClusterInfoClassForRestore clusterInfoObj)
    {
        boolean reconfigSuccess = false;

        ManagedEntity haCluster = clusterInfoObj.cluster;
        List<HostSystem> cluHosts = clusterInfoObj.hosts;
        String cluName = haCluster.getName();

        try {
            if (reconfigClusterWithAdvOption(clusterInfoObj.ccr, clusterInfoObj.clusterConfigInfo)) {
                System.out.println("Successfully added advanced option: \"" + HA_SSL_CONFIG_OPTION
                    + "\"  with value: \"" + HA_SSL_OP_VAL + "\" to Cluster: " + cluName);

                // Reconfigure HA on all hosts
                Map<Boolean, List<HostSystem>> reconfigHostsResultMap = reconfigureHAOnCluHosts(cluHosts);

                if (reconfigHostsResultMap.keySet().contains(Boolean.TRUE)) {
                    System.out.println("Reconfigure HA on ALL clustered hosts completed");

                    // Scan for the FDM port and check if indeed changes are applied
                    reconfigSuccess = true;
                } else {
                    System.err.println("Reconfigure HA on clustered hosts failed ...");
                }
            } else {
                System.err
                    .println("Failed to add advanced option: " + HA_SSL_CONFIG_OPTION + " to Cluster: " + cluName);
            }
        } catch (Exception e) {
            System.err.println("Caught exception while updating cluster: " + cluName + " with SSL advanced option");
        }

        return reconfigSuccess;
    }

    /**
     * Add advanced option to disable/enable SSL protocol
     */
    private boolean
    reconfigClusterWithAdvOption(ClusterComputeResource haCcr, ClusterConfigInfoEx oriCluConfigInfo)
    {
        boolean reconfigSuccess = false;
        ClusterConfigSpecEx newSpec = new ClusterConfigSpecEx();

        ClusterDasConfigInfo oriCluDasConfigInfo = oriCluConfigInfo.getDasConfig();
        OptionValue[] oriAdvancedOptions = oriCluDasConfigInfo.getOption();

        // Add advanced option, along with pre-existing advanced options
        OptionValue[] newAdvancedOptions;
        OptionValue newOptionValue = new OptionValue();
        newOptionValue.setKey(HA_SSL_CONFIG_OPTION);
        newOptionValue.setValue(HA_SSL_OP_VAL);

        outer: if (oriAdvancedOptions != null) {
            newAdvancedOptions = new OptionValue[oriAdvancedOptions.length + 1];
            for (int i = 0; i < oriAdvancedOptions.length; i++) {
                // Check if the advanced option already exists
                if ((oriAdvancedOptions[i].getKey().equals(HA_SSL_CONFIG_OPTION))
                    && (oriAdvancedOptions[i].getValue().equals(HA_SSL_OP_VAL))) {
                    System.out.println("Cluster already has the required advanced options added");
                    reconfigSuccess = true;
                    break outer;
                }
                newAdvancedOptions[i] = oriAdvancedOptions[i];
            }
            newAdvancedOptions[oriAdvancedOptions.length] = newOptionValue;
        } else {
            newAdvancedOptions = new OptionValue[1];
            newAdvancedOptions[0] = newOptionValue;
        }

        // If the advanced option does not exist already, proceed further
        if (!reconfigSuccess) {
            oriCluDasConfigInfo.setOption(newAdvancedOptions);
            newSpec.setDasConfig(oriCluDasConfigInfo);

            try {
                /*
                 * reconfigureComputeResource_Task(newSpec, modify)
                 * -- newSpec : A set of configuration changes to apply to the compute resource
                 * -- modify :
                 * (i) if set to "true". All SET properties from the newSpec is applied. And all UNSET property has
                 * no effect on the existing property value in the cluster configuration.
                 * (ii) if set to "faslse". All SET properties from the newSpec is applied. And all UNSET property
                 * portions of the specification will result in UNSET or default portions of the configuration.
                 *
                 * For the current case, we'll pass "true" with spec containing changes to ONLY Advanced options area.
                 * Rest all will be unset - and per the API call behavior, even after reconfig cluster call, other
                 * properties/settings/configurations (like DRS/DPM/Rules etc) would continue to exist unharmed.
                 */
                Task reconfigCluTask = haCcr.reconfigureComputeResource_Task(newSpec, true);

                // Monitor the task status
                int count = 10;
                while (count > 0) {
                    TaskInfoState taskState = reconfigCluTask.getTaskInfo().getState();
                    if (taskState.equals(TaskInfoState.queued) || taskState.equals(TaskInfoState.running)) {
                        System.out
                            .println("Cluster Reconfiguration task is still running, wait for the task to complete");
                        Thread.sleep(1000 * 2);
                        --count;
                    } else if (taskState.equals(TaskInfoState.success)) {
                        System.out.println("Reconfigure Cluster task succeeded");
                        reconfigSuccess = true;
                        cluAdvOpAdded = true;
                        break;
                    } else if (taskState.equals(TaskInfoState.error)) {
                        System.out.println("Reconfigure Cluster task Failed");
                        break;
                    }
                }

            } catch (Exception e) {
                System.err.println("Caught exception while reconfiguring cluster");
                e.printStackTrace();
            }
        }

        return reconfigSuccess;
    }

    /**
     * Add advanced option to disable/enable SSL protocol
     */
    private boolean
    removeClusterAdvOption(ClusterComputeResource haCcr, ClusterConfigInfoEx oriCluConfigInfo)
    {
        boolean reconfigSuccess = false;
        ClusterConfigSpecEx newSpec = new ClusterConfigSpecEx();

        // HA
        ClusterDasConfigInfo oriCluDasConfigInfo = oriCluConfigInfo.getDasConfig();
        OptionValue[] oriAdvancedOptions = oriCluDasConfigInfo.getOption();

        // Add advanced option, along with pre-existing advanced options
        OptionValue[] newAdvancedOptions;
        OptionValue newOptionValue = new OptionValue();
        newOptionValue.setKey(HA_SSL_CONFIG_OPTION);

        if (enableSsl) {
            // Since request came for Enabling SSLv3, revert option must be to Disable SSLv3
            newOptionValue.setValue(DEFAULT_DISABLE_SSLOP_VAL);
        } else {
            // Since request came for Disabling SSLv3, revert option must be to Enable SSLv3
            newOptionValue.setValue(DEFAULT_ENABLE_SSLOP_VAL);
        }

        if (oriAdvancedOptions != null) {
            boolean foundAdvOpt = false;
            for (int i = 0; i < oriAdvancedOptions.length; i++) {
                // Check if the advanced option already exists
                if (oriAdvancedOptions[i].getKey().equals(HA_SSL_CONFIG_OPTION)) {
                    foundAdvOpt = true;
                    break;
                }
            }

            if (!foundAdvOpt) {
                // Advanced option does not exist in Original Cluster Config,
                // set default advanced option to revert the change: Default supported protocols
                newAdvancedOptions = new OptionValue[oriAdvancedOptions.length + 1];
                for (int i = 0; i < oriAdvancedOptions.length; i++) {
                    newAdvancedOptions[i] = oriAdvancedOptions[i];
                }
                newAdvancedOptions[oriAdvancedOptions.length] = newOptionValue;
            } else {
                // Advanced option already exists in Original Cluster Config, Use it as is to revert the change
                newAdvancedOptions = new OptionValue[oriAdvancedOptions.length];
                for (int i = 0; i < oriAdvancedOptions.length; i++) {
                    newAdvancedOptions[i] = oriAdvancedOptions[i];
                }
            }
        } else {
            /*
             * There were NO advanced Option set INCLUDING HA-SSL option.
             * Set the advanced option to revert the change per request received
             */
            newAdvancedOptions = new OptionValue[1];
            newAdvancedOptions[0] = newOptionValue;
        }

        oriCluDasConfigInfo.setOption(newAdvancedOptions);
        newSpec.setDasConfig(oriCluDasConfigInfo);

        try {
            /*
             * reconfigureComputeResource_Task(newSpec, modify)
             * -- newSpec : A set of configuration changes to apply to the compute resource
             * -- modify :
             * (i) if set to "true". All SET properties from the newSpec is applied. And all UNSET property has
             * no effect on the existing property value in the cluster configuration.
             * (ii) if set to "faslse". All SET properties from the newSpec is applied. And all UNSET property
             * portions of the specification will result in UNSET or default portions of the configuration.
             *
             * For the current case, we'll pass "true" with spec containing changes to ONLY Advanced options area.
             * Rest all will be unset - and per the API call behavior, even after reconfig cluster call, other
             * properties/settings/configurations (like DRS/DPM/Rules etc) would continue to exist unharmed.
             */
            Task reconfigCluTask = haCcr.reconfigureComputeResource_Task(newSpec, true);

            // Monitor the task status
            int count = 10;
            while (count > 0) {
                TaskInfoState taskState = reconfigCluTask.getTaskInfo().getState();
                if (taskState.equals(TaskInfoState.queued) || taskState.equals(TaskInfoState.running)) {
                    System.out.println("Cluster Reconfiguration task is still running, wait for the task to complete");
                    Thread.sleep(1000 * 2);
                    --count;
                } else if (taskState.equals(TaskInfoState.success)) {
                    System.out.println("Reconfigure Cluster task succeeded");
                    reconfigSuccess = true;
                    cluAdvOpAdded = true;
                    break;
                } else if (taskState.equals(TaskInfoState.error)) {
                    System.out.println("Reconfigure Cluster task Failed");
                    break;
                }
            }

        } catch (Exception e) {
            System.err.println("Caught exception while reconfiguring cluster");
            e.printStackTrace();
        }

        return reconfigSuccess;
    }

    /**
     * Class to handle Host Reconfig HA tasks in threaded fashion
     */
    private class ThreadReconfigHA extends Thread
    {
        private static final int FDM_RECONFIG_TIMEOUT = 600; // 10 Minutes
        private static final int LOOP_DELAY = 20; // 20 seconds sleep for each iteration
        HostSystem hostSys;
        boolean isHostReconfigured = false;

        ThreadReconfigHA(HostSystem hostSystem) {
            hostSys = hostSystem;
        }

        @Override
        public void
        run()
        {
            String hostName = hostSys.getName();
            System.out.println("[" + hostName + "] Trigger Reconfig HA operation on host ...");
            try {
                Task reconfigHATask = hostSys.reconfigureHostForDAS();

                // Monitor the task status
                int count = FDM_RECONFIG_TIMEOUT / LOOP_DELAY; // 450 seconds timeout for HA Reconfig task
                while (count > 0) {
                    TaskInfoState reconfigHaTaskState = reconfigHATask.getTaskInfo().getState();
                    if (reconfigHaTaskState.equals(TaskInfoState.queued)
                        || reconfigHaTaskState.equals(TaskInfoState.running)) {
                        System.out.println(
                            "[" + hostName
                                + "] Reconfig HA task on host is still running, wait for the task to complete");
                        Thread.sleep(1000 * LOOP_DELAY);
                        --count;
                    } else if (reconfigHaTaskState.equals(TaskInfoState.success)) {
                        System.out.println("[" + hostName + "] Reconfig HA on Host task succeeded");
                        isHostReconfigured = true;
                        break;
                    } else if (reconfigHaTaskState.equals(TaskInfoState.error)) {
                        System.out.println("[" + hostName + "] Reconfig HA on Host task FAILED");
                        break;
                    }
                }

            } catch (Exception e) {
                System.err.println("[" + hostName + "] Caught exception while reconfiguring HA on host");
            }

        }
    }

    /**
     * Reconfigure HA on all ESXi hosts
     */
    private Map<Boolean, List<HostSystem>>
    reconfigureHAOnCluHosts(List<HostSystem> allHostSys)
    {
        Boolean allHostsConfigured = false;
        List<ThreadReconfigHA> allHAThreadObj = new ArrayList<ThreadReconfigHA>();
        List<HostSystem> listOfHaReconfigFailedHosts = new ArrayList<HostSystem>();
        int reconfigSuccessHostCnt = 0;

        try {
            for (HostSystem tempHostSys : allHostSys) {
                ThreadReconfigHA reconfigHAThreadObj = new ThreadReconfigHA(tempHostSys);
                reconfigHAThreadObj.start();
                allHAThreadObj.add(reconfigHAThreadObj);
            }

            // Now wait for all threads to complete
            for (ThreadReconfigHA tempReconfigThreadObj : allHAThreadObj) {
                tempReconfigThreadObj.join();
                if (tempReconfigThreadObj.isHostReconfigured) {
                    ++reconfigSuccessHostCnt;
                } else {
                    listOfHaReconfigFailedHosts.add(tempReconfigThreadObj.hostSys);
                }
            }
        } catch (Exception e) {
            System.err.println("Caught exception while reconfiguring HA on clustered hosts");
        }

        // Check if all reconfig HA operation on hosts gone through fine
        if ((listOfHaReconfigFailedHosts.size() == 0) && (reconfigSuccessHostCnt == allHostSys.size())) {
            allHostsConfigured = true;
        }

        Map<Boolean, List<HostSystem>> resultMapObj = new HashMap<Boolean, List<HostSystem>>();
        resultMapObj.put(allHostsConfigured, listOfHaReconfigFailedHosts);

        return resultMapObj;
    }

    /**
     * Class to hold a particular Host's SSH connection information and whether SSH service on
     * host was started. If SSH service is started by utility, it'll be restored to its original state.
     */
    public class HostSSHInfoClass
    {
        String hostName;
        HostSystem hostSys;
        Connection hostSshConnObj;
        boolean restoreSSHServiceState;
    }

    /**
     * Class to store cluster information, to be used in the event of failure to restore cluster to
     * original state (configuration)
     */
    class ClusterInfoClassForRestore
    {
        ManagedEntity cluster;
        List<HostSystem> hosts;
        ClusterConfigInfoEx clusterConfigInfo;
        ClusterComputeResource ccr;
    }

    /**
     * Class to hold the SSL configuration result of a host.
     * Consist of hostname, port configured - previous SSL versions, TLS versions after updation
     */
    class HostSSLResultHolderClass
    {
        Integer port;
        String beforeProtoList;
        String afterProtoList;
        String clusterName;
    }

    class OverallResultHolderClass
    {
        String cluName;
        Map<String, String> beforeTLSProtos;
        Map<String, String> afterTLSProtos;
    }
}