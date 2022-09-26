import json
import os
import sys
import time
from dataclasses import dataclass
import StraceModule.StraceModuleMain as straceModule
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


def readJson():
    f = open("caps.json")
    data: dict = json.load(f)

    if {"version", "device", "udid", "appName", "app", "alertButtonsToAccept", "buttonsToIgnore"} == data.keys():
        desired_caps = dict(
            platformName='iOS',
            platformVersion=data["version"],
            deviceName=data["device"],
            automationName='xcuitest',
            udid=data["udid"],
            wdaLaunchTimeout="120000",
            noReset="true"
        )
        #return desired_caps, data["appName"], data["udid"], data["app"], data["alertButtonsToAccept"], data["buttonsToIgnore"]
        return jsonElements(desired_caps, data["appName"], data["udid"], data["app"], data["alertButtonsToAccept"], data["buttonsToIgnore"])
    else:
        print("error! missing arguments inside caps.json! Follow the instruction!")
        return None


def resignWDA(udid):
    print(
        "durante l'installazione di WebDriverAgent spostarsi su impostazioni > generali > gestione profili e dispositivo"
        " ed autorizzare il profilo 'Apple Development'")
    time.sleep(3)
    print("avvio test e resigning...")
    currentDir = os.getcwd()
    os.chdir(
        "/Applications/Appium Server GUI.app/Contents/Resources/app/node_modules/appium/node_modules/appium-webdriveragent")
    os.system("xcodebuild "
              "-quiet "
              "-project WebDriverAgent.xcodeproj "
              "-scheme WebDriverAgentRunner "
              f"-destination 'id={udid}' "
              "-allowProvisioningUpdates")
    os.chdir(currentDir)


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
            val = input("do you want to resign the WebDriverAgent [WDA] App? (y/n)")
            if val == "y":
                print("## starting resign ##")
                resignWDA(jsonVals.udid)
                print("## resign completed ##")
                break

            if val == "n":
                break

        while True:
            val = input("do you want to install the app? (y/n)")
            if val == "y":
                if jsonVals.app == "":
                    print("error: 'app' is empty in the configuration file. Please check caps.json and run this program again")
                    sys.exit()
                else:
                    print("## starting installation ##")
                    installApp(jsonVals.app, jsonVals.udid)
                    print("## installation completed ##")
                break

            if val == "n":
                break

        print("## starting test ##")
        appIdentifier = straceModule.appConnection(jsonVals.appName)
        appiumModule = am.AppiumModule()
        if appIdentifier is not None:
            appiumModuleProcess = Process(target=appiumModule.startAppiumModule,
                                          args=(jsonVals.desiredCaps, appIdentifier, jsonVals.alertButtonsToAccept, jsonVals.buttonsToIgnore))
            appiumModuleProcess.start()
            straceModule.startStraceModule()
            appiumModuleProcess.join()
    else:
        print("closing...")
    print("## test ended ##")
