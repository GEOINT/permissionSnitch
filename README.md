permissionSnitch
================

JVM SecurityManager "snitch", useful in determining which permissions are 
required for an application.  

The SnitchSecurityManager implementation approves all requested permissions, 
logging the requested permission in the processes.

**WARNING:**

This SecurityManager implementation <b>should not</b> be used in production.
The purpose of this class is to figure out which permissions an application
needs, useful in debugging, documenting, and preparing to deploy a 3rd party
application in a security managed environment. Again, this implementation is
**not** secure for production use.

#How to use the SnitchSecurityManager

##JVM Property
Most of the time, you'll want to use the SnitchSecurityManager in a similar
environment the target application will be running. For example, if the
application in question is a war, you'll want to run it within an application
server that can run that war. The most portable way to make use of the
SnitchSecurityManager is to set the *java.security.manager* JVM
property with the fully qualified class name:

*-Djava.security.manager=org.geoint.security.SnitchSecurityManager*

##Programmatic
Another option is to set the SecurityManager using the 
System#setSecurityManager()  method. You'll
probably want to do this at/near startup of the application, to ensure you
get everything.