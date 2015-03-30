==============
JCA Examples
==============
This projects includes some encryption/decryption examples using the JCA APIs.

**Requirements**
- JDK 1.7
- JCE Unlimited Strength Jurisdiction Policy Files for JDK/JRE 7

**How to install JCE extention files**  
1. Go to the Oracle Java download page http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html  
2. Accept license agreement and download the UnlimitedJCEPolicyJDK7.zip  
3. Unzip the downloaded zip  
4. Copy local_policy.jar and US_export_policy.jar to the $JAVA_HOME/jre/lib/security (Note: these jars will be already there so you have to overwrite them)  

**Checking out from github**
  
### GIT  
> git clone https://github.com/giuseppeurso-eu/java-security  

### SUBVERSION  
> svn co https://github.com/giuseppeurso-eu/java-security/trunk   java-security  

**Run Maven build**  
```
> cd java-security/jca
> mvn install
```
**How to install JCE extention files**  
1. Go to the Oracle Java download page http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html  
2. Accept license agreement and download the UnlimitedJCEPolicyJDK7.zip  
3. Unzip the downloaded zip  
4. Copy local_policy.jar and US_export_policy.jar to the $JAVA_HOME/jre/lib/security (Note: these jars will be already there so you have to overwrite them)
**How to install JCE extention files**  
1. Go to the Oracle Java download page http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html  
2. Accept license agreement and download the UnlimitedJCEPolicyJDK7.zip  
3. Unzip the downloaded zip  
4. Copy local_policy.jar and US_export_policy.jar to the $JAVA_HOME/jre/lib/security (Note: these jars will be already there so you have to overwrite them)
