import json
import os
import time
import StraceModule.StraceModuleMain as straceModule
from multiprocessing import Process
import AppiumModule


def defineCaps():
    f = open("caps.json")
    data = json.load(f)

    desired_caps = dict(
        platformName='iOS',
        platformVersion=data["version"],
        deviceName=data["device"],
        automationName='xcuitest',
        udid=data["udid"],
        wdaLaunchTimeout="120000",
        noReset="true"
    )
    return desired_caps, data["appName"], data["udid"], data["app"]


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
    desiredCaps, appName, udid, app = defineCaps()

    while True:
        val = input("do you want to resign the WebDriverAgent [WDA] App? (y/n)")
        if val == "y":
            print("## starting resign ##")
            resignWDA(udid)
            print("## resign completed ##")
            break

        if val == "n":
            break

    while True:
        val = input("do you want to install the app? (y/n)")
        if val == "y":
            print("## starting installation ##")
            installApp(app, udid)
            print("## installation completed ##")
            break

        if val == "n":
            break

    print("## starting test ##")
    appIdentifier = straceModule.appConnection(appName)
    if appIdentifier is not None:
        appiumModuleProcess = Process(target=AppiumModule.startAppiumModule, args=(desiredCaps, appIdentifier))
        appiumModuleProcess.start()
        straceModule.startStraceModule()
        appiumModuleProcess.join()
    else:
        print("closing...")
    print("## test ended ##")
