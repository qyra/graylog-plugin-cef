sudo yum install maven
will install the prereqs
To get this to build, you will need to enable the proxy for maven

The configuration file is at:

`/etc/maven/settings.xml`

For simplicity, I put an edited copy of it in the source directory. You can use
it by calling

`mvn -s settings.xml package`

```
  <!-- proxies
   | This is a list of proxies which can be used on this machine to connect to the network.
   | Unless otherwise specified (by system property or command-line switch), the first proxy
   | specification in this list marked as active will be used.
   |-->
  <proxies>
    <proxy>
      <id>optional</id>
      <active>true</active>
      <protocol>http</protocol>
      <username></username>
      <password></password>
      <host>cawnpxgomc0001.me.mbgov.ca</host>
      <port>80</port>
      <nonProxyHosts>local.net|some.host.com</nonProxyHosts>
    </proxy>
  </proxies>
```

I uncommented the proxies zone, and added the correct host.
If you are running this out of the dev environment, you'll have to 
add your username and password in the corresponding fields.
