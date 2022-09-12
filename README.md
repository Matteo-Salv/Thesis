# Automatic Dynamic Analysis on iOS devices
### Bachelor degree thesis
### Computer Engineering - Software Platforms and Cybersecurity
### University of Genoa
## Prerequisites
* macOS device with the following dependencies already installed: 
  * [Homebrew](https://brew.sh)
  * Python 3.8+
  * Frida (pip install frida)
  * ios-deploy (brew install ios-deploy)
  * lxml (pip install lxml)
  * frida-tools (pip install frida-tools)
  * [Appium Desktop](https://github.com/appium/appium-desktop/releases)
  * xCode, for the WebDriverAgent configuration, already included in Appium Desktop. check [full manual configuration chapter here](https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/)
* physical jailbroken iDevice (with no or limited effort this script should work also on iPadOS)
  * [Frida installed from Cydia](https://frida.re/docs/ios/)
## Before starting: a note regarding the app sign on physical iDevices
Warning! Due to Apple restrictions if you want to install an App with this script, you must sign it with a valid 
developer certificate. You can use directly xCode (if you have the source code ready
to be compiled) or alternatively sign directly the .App installer file with tools like [iOS App Signer](https://dantheman827.github.io/ios-app-signer/).

If you don't want to sign and/or use the installation option available with this program take a look on
Filza tweak (available on Cydia) or Cydia Impactor (only with a Paid developer profile) and then skip the installation step.
## Instructions
1. Connect the device under test with a USB cable and disable the automatic lock (iOS 14: *settings>Screen and Brightness>* set *Automatic lock* on *'never'*)
2. Start Appium Desktop making sure that the corresponding parameters are the same as the following image:
![Appium default configuration](/docs/appium_default.png)
3. Edit the requested configuration parameters in *caps.json*
## Disclaimer
This project has been developed and tested on a Intel Mac with macOS12 (Monterey).
It should work with minimum effort on Apple Silicon, but there are no tests so far in this sense.

the strace module is not developed by me, but mostly forked and edited from another project freely available on Github.
For more info, take a look on the corresponding LICENSE.

## Testing Environment:
* iPhone 6s with iOS 14.4.2 semi-tethered jailbroken with checkra1n
* macbook pro 2016 with Intel i5-6360U @ 2.00GHz updated to macOS 12 Monterey, xCode 13 and python 3.9