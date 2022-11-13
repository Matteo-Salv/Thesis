# Automatic Dynamic Analysis on iOS devices
### Bachelor degree thesis, Computer Engineering - Software Platforms and Cybersecurity
### University of Genoa
## Prerequisites
* macOS device with the following dependencies already installed: 
  * [Homebrew](https://brew.sh)
  * Python 3.8+
  * Frida (pip install frida)
  * ios-deploy (brew install ios-deploy)
  * carthage (brew install carthage)
  * lxml (pip install lxml)
  * frida-tools (pip install frida-tools)
  * [Appium](https://appium.io/docs/en/about-appium/getting-started/?lang=it)
    * NOTE: Appium Desktop is note compatible with xCode 14 suite. For my tests I used Appium v2.0 beta. If you're in the same situation,
    take a look on the section [About Appium 2](##About Appium 2)
  * xCode, for the WebDriverAgent configuration, already included in Appium. check [full manual configuration chapter here](https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/)
    and [About Appium 2](##About Appium 2) if you're using Appium 2
* physical jailbroken iDevice (with no or limited effort this script should work also on iPadOS)
  * [Frida installed from Cydia](https://frida.re/docs/ios/)
## Before starting: a note regarding the app sign on physical iDevices
Warning! Due to Apple restrictions if you want to install an App with this script, you must sign it before with a valid 
developer certificate. You can use directly xCode (if you have the source code ready
to be compiled) or alternatively sign directly the .App installer file with tools like [iOS App Signer](https://dantheman827.github.io/ios-app-signer/).

If you don't want to sign and/or use the installation option available with this program take a look on
Filza tweak (available on Cydia) or Cydia Impactor (only with a Paid developer profile) and then skip the installation step.
## Instructions
1. Connect the device under test with a USB cable and disable the automatic lock (iOS 14: *settings>Screen and Brightness>* set *Automatic lock* on *'never'*)
2. Start Appium
3. Edit the requested configuration parameters in *caps.json*:
   * version = the iOS version installed
   * udid
   * app = path to the .app you want to test (needed only if you want to install it with this program)
   * appName = the name of the application
   * alertButtonsToAccept = the name of the buttons inside an alert you want to automatically accept, separated by a ','
   * buttonsToIgnore = the name of the buttons you want to ignore, separated by a ','
   * systemCallsFile = the file containing the system calls to track
   * wdaDir = path to appium-webdriveragent (mandatory only if necessary to manually install WDA)
   * timeout = default 600s
   
   please note that *version, udid and appName* are mandatory. If you don't want to set the other options, you can 
leave them blank.
Example:
```
{"version":"14.4",
  "device":"iPhone 6s",
  "udid":"a123456789bcd87654e21",
  "app":"/Users/foo.app",
  "appName":"foo",
  "alertButtonsToAccept": "OK,ok,allow,Allow",
  "buttonsToIgnore": ""
  "systemCallsFile": "syscall.txt",
  "wdaDir": "/Users/user/.appium/node_modules/appium-xcuitest-driver/node_modules/appium-webdriveragent",
  "timeout": 180
}
```
inside systemCallsFile insert the name of the corresponding file containing all the syscalls you want to track and loaded inside
"SystemCalls" folder. To understand how to format it, take a look on existing syscall.txt and syscall_edited.txt.
## Disclaimer
This project has been developed and tested on a Intel Mac with macOS12 (Monterey).
It should work with minimum effort on Apple Silicon, but there are no tests so far in this sense.

the strace module has not been entirely developed by me, but partially forked and edited from another project freely available on Github.
For more info, take a look on the corresponding LICENSE.
## Testing Environment:
* iPhone 6s with iOS 14.4.2 semi-tethered jailbroken with checkra1n
* macbook pro 2016 with Intel i5-6360U @ 2.00GHz updated to macOS 12 Monterey, xCode 14 and python 3.10
## About Appium 2
Currently (october 2022) Appium Desktop and Appium 1.x doesn't support xCode 14. If you're in the same situation, after
the configuration of node.js and NPM use the following guide for Appium installation and execution:
1. npm install -g appium@next
2. appium plugin install execute-driver
3. appium driver install xcuitest
Then check the installation with *appium-doctor*:
   1. npm install appium-doctor
   2. appium-doctor --ios

eventually fix any mandatory dependency.

Please note that after the first installation it is necessary to sign the WebDriverAgent bundled with Appium through xcodebuild.
Check [this guide](https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/), in particular the chapter
'full manual configuration'. The command to resign is the following:
```
xcodebuild -project WebDriverAgent.xcodeproj -scheme WebDriverAgentRunner -destination 'id=123456789abcdef' -allowProvisioningUpdates test
```
The WebDriverAgent folder is the following:
```
/Users/*user*/.appium/node_modules/appium-xcuitest-driver/node_modules/appium-webdriveragent
```
After that, to run Appium:
```
appium -pa /wd/hub --use-plugins execute-driver
```