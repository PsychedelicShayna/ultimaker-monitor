# Ultimaker Monitor
This tool uses the Ultimaker 3's WebAPI to wirelessly poll information about the 3D printer's state, such as temperature, memory usage, print status, print history, system log, etc. It also allows for some basic control over the 3D printer's current printjob, as well as the ability to upload printjobs in GCode format.

# Building
The interface is built using Qt5, so you will need a Qt environment in order to build this. If you already have one, then building it shouldn't be too much of a hassle. The repository already comes with the necessary dependencies, just ensure that the link directory for curl in the project file is set correctly, since link directories are relative to the makefile location, so if your build directory is elsewhere, make sure you navigate upwards from your build directory, and into where the Curl dependencies are.

_Footnote: this was designed with 64-bit in mind, I can't confirm if a 32-bit build would work as I do not have a 32-bit copy of Curl_

## Screenshot
![](screenshots/ultimaker-monitor_UQNUYtjfxj.png?raw=true)
