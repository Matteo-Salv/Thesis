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
    print("Attenzione: Durante l'installazione potrebbe rendersi necessario spostarsi su impostazioni > generali > "
          "gestione profili e dispositivo ed autorizzare il profilo 'Apple Development' con cui si è "
          "firmato precedentemente l'app")
    print("## Avvio installazione ##")
    os.system(f"ios-deploy -i {udid} -b '{appDir}'")
    print("## installazione completata ##")
    time.sleep(3)


if __name__ == '__main__':
    desiredCaps, appName, udid, app = defineCaps()

    while True:
        val = input("Effettuare il resigning di WebDriverAgent? (y/n)")
        if val == "y":
            print("## avvio resigning ##")
            resignWDA(udid)
            print("## resigning completato ##")
            break

        if val == "n":
            break

    while True:
        val = input("Avviare l'installazione dell'app? (y/n)")
        if val == "y":
            print("## avvio installazione ##")
            installApp(app, udid)
            print("## installazione completata ##")
            break

        if val == "n":
            break

    print("## esecuzione del test ##")
    appIdentifier = straceModule.appConnection(appName)
    if appIdentifier is not None:
        appiumModuleProcess = Process(target=AppiumModule.startAppiumModule, args=(desiredCaps, appIdentifier))
        appiumModuleProcess.start()
        straceModule.startStraceModule()
        appiumModuleProcess.join()
    else:
        print("closing...")
    print("## test terminato ##")
