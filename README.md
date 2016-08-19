# vSphere HA (FDM) SSLv3 Configuration Utility for VMware ESXi5.5
Utility program for SSLv3 Security Protocol Configuration on vSphere HA (FDM) service.  
Go through "vSphere-HA-FDM-SSL-Config-README.pdf" for details on the utility.

### 1. Features
* Automatically add the advanced option _das.config.vmacore.ssl.sslOptions_ on all HA enabled cluster and reconfigure HA on all Clustered ESXi hosts for changes to take effect.
* Utility has inbuilt scanner intelligence (TestSSLServer) for scanning port to determine what protocols are already enabled and whether configuration was successful.
* Utility reverts the configuration changes done, to restore the state as it was before, when there is a failure in doing configuration changes.
* Utility can be used to apply security protocol configuration either for entire Cluster or none.
* Utility generates report (csv file) with all Clustered ESXi server’s configuration result such as what security protocols were enabled earlier, after configuration what protocols are enabled and etc.

### 2. Different options available with the Utility
* Enable SSLv3 on vSphere HA/FDM port 8182
* Disable SSLv3 on vSphere HA/FDM port 8182

### 3. Prerequisites for running Utility
* vCenter Server and ESXi Server services/ports are all configured with same version of security protocol(s). (If there are any exceptions, those are automatically considered)
* Take backup of all vSphere HA enabled Clusters configuration (settings, rules and etc) 
* Java runtime environment /JDK where Java version is 1.7.0_45 or higher.

### 4. How to run the Utility?
##### Run from Dev IDE
* Import files under the _src/com/vmware/fdmsecprotomgmt_ folder into your IDE.
* Required libraries are embedded within Runnable-Jar/fdmsecprotomgmt.jar, extract & import the libraries into the project.
* Run the utility from 'RunApp' program by providing arguments like:   
  For enabling SSLv3: _--vsphereip 1.2.3.4  --username adminUser --password dummyPasswd --hostsinfofile <pathToHostsListfile> enablessl_  
  For disabling SSLv3: _--vsphereip 1.2.3.4  --username adminUser --password dummyPasswd --hostsinfofile <pathToHostsListfile> disablessl_   
 
##### Run from Pre-built Jars
* Copy/Download the _fdmsecprotomgmt.jar_ from Runnable-jar folder (from the uploaded file) and unzip on to local drive folder say c:\SecurityProtoMgmt
* Open a command prompt and cd to the folder, lets say
cd SecurityProtoMgmt
* Run a command like shown below to see various usage commands,  
C:\SecurityProtoMgmt>java -jar fdmsecprotomgmt.jar --help
