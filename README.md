# wake-on-lan.php
Send magic packet from php to wake up a host using "Wake on Lan"

![Wake-On_Lan Screenshot](wake-on-lan.png "wake-on-lan screenshot")

```index.php``` started as a ___one file drop in___ tool for waking up computers when they are suspended.


# Requirements
* Windows Operation System
* XAMPP or IIS
* PHP5 or PHP7
* Internet connection for CDN includes (.js, .css)

# Installation
* Either clone the repository or download the zip file
* Copy the file ```index.php``` to a directory on your web server.


# Setup
Open your favorite browser and navigate to the ```index.php``` url.
Now you can start adding your the hosts you want to wake.

* _Wake up!_ - send a magic packet for the selected host.

# Caveat
Does not run under linux. Because the linux user used to run php code on the server side usually has very limited permission it cannot create the raw socket to send the magic packet.

# License
```index.php``` is published under [MIT](LICENSE) license.
