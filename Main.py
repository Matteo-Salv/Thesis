import json
import os
import sys
import time
from dataclasses import dataclass
import StraceModule.StraceModule as sm
from multiprocessing import Process
import AppiumModule as am


@dataclass
class jsonElements:
    desiredCaps: dict
    appName: str
    udid: str
    app: str
    alertButtonsToAccept: str
    buttonsToIgnore: str
    sysCallsFile: str
    wdaDir: str

    def __post_init__(self):
        if self.wdaDir is None:
            self.wdaDir = ""
        if self.alertButtonsToAccept is None:
            self.alertButtonsToAccept = ""
        if self.buttonsToIgnore is None:
            self.buttonsToIgnore = ""


def resignWDA(udid, wdaDir):
    print("warning: during the WebDriverAgent installation process it may be necessary to go to 'settings > general > "
          "profile and device management' and then authorize the corresponding 'Apple Development' profile with which "
          "the app was previously signed")
    time.sleep(3)
    print("starting resigning...")
    currentDir = os.getcwd()
    os.chdir(wdaDir)
    os.system("xcodebuild "
              "-quiet "
              "-project WebDriverAgent.xcodeproj "
              "-scheme WebDriverAgentRunner "
              f"-destination 'id={udid}' "
              "-allowProvisioningUpdates")
    os.chdir(currentDir)


def readJson():
    f = open("caps.json")
    data: dict = json.load(f)

    if all(elem in data for elem in ("version", "device", "udid", "appName", "app", "systemCallsListFile")):
    # if {"version", "device", "udid", "appName", "app", "systemCallsListFile"} in data.keys():
        desired_caps = dict(
            platformName='iOS',
            platformVersion=data["version"],
            deviceName=data["device"],
            automationName='xcuitest',
            udid=data["udid"],
            wdaLaunchTimeout="120000",
            noReset="true"
        )
        return jsonElements(desired_caps, data["appName"], data["udid"], data["app"], data["alertButtonsToAccept"],
                            data["buttonsToIgnore"], data["systemCallsListFile"], data["wdaDir"])
    else:
        print("error! missing mandatory arguments inside caps.json! Follow the instruction!")
        return None


def installApp(appDir, udid):
    print("warning: during the installation process it may be necessary to go to 'settings > general > "
          "profile and device management' and then authorize the corresponding 'Apple Development' profile with which "
          "the app was previously signed")
    os.system(f"ios-deploy -i {udid} -b '{appDir}'")
    time.sleep(3)


if __name__ == '__main__':
    if readJson() is not None:
        jsonVals = readJson()

        while True:
            val = input("do you want to install the app? (y/n)")
            if val == "y":
                if jsonVals.app == "":
                    print(
                        "error: 'app' is empty in the configuration file. Please check caps.json and run this program again")
                    sys.exit()
                else:
                    print("## starting installation ##")
                    installApp(jsonVals.app, jsonVals.udid)
                    print("## installation completed ##")
                break

            if val == "n":
                break

        if jsonVals.wdaDir != "":
            while True:
                val = input(
                    "do you want to resign the WebDriverAgent [WDA] App? (y/n) [necessary only if Appium has some issues about WDA connection/installation]:")
                if val == "y":
                    print("## starting resign ##")
                    resignWDA(jsonVals.udid, jsonVals.wdaDir)
                    print("## resign completed ##")
                    break

                if val == "n":
                    break
        else:
            print("wda directory ('wdaDir' property) not specified inside json options file, skipping WDA installation")

        print("## starting test ##")
        straceModule = sm.StraceModule()
        appIdentifier = straceModule.appConnection(jsonVals.appName)
        appiumModule = am.AppiumModule()
        if appIdentifier is not None and straceModule.createSysCallsList(jsonVals.sysCallsFile):
            appiumModuleProcess = Process(target=appiumModule.startAppiumModule,
                                          args=(jsonVals.desiredCaps, appIdentifier, jsonVals.alertButtonsToAccept,
                                                jsonVals.buttonsToIgnore))
            appiumModuleProcess.start()
            straceModule.startStraceModule()
            appiumModuleProcess.join()
            print("closing...")
            sys.exit()
    else:
        print("closing...")
