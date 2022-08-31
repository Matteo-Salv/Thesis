import ctypes
import json
import multiprocessing
import os
import sys
import warnings

import frida
from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from lxml import etree as eT
import random
import time
import iOS_strace.strace as strace
from multiprocessing import Process

# necessario in quanto il metodo root.find() di lxml crea delle futurewarning
warnings.simplefilter(action='ignore', category=FutureWarning)

buttonsToAutomaticallyAccept = ['OK', 'ok', 'allow', 'Allow']


def appiumModule(desiredCaps, appName):

    print("modulo Appium avviato con successo")
    print("[Appium]: connessione all'app in corso...")
    appiumDriver = webdriver.Remote('http://0.0.0.0:4723/wd/hub', desiredCaps)
    device = frida.get_usb_device()
    apps = device.enumerate_applications()
    for app in apps:
        if appName == app.name:
            bundleID = app.identifier
            break
    print("[Appium]: ...connessione completata")
    accessibleElements = list()
    while True:
        root: eT._Element = eT.XML(appiumDriver.page_source.encode())

        # 0 is not installed. 1 is not running. 2 is running in background or suspended.
        # 3 is running in background. 4 is running in foreground
        appState = appiumDriver.query_app_state(bundleID)
        if appState == 4:
            if alert := root.find(".//XCUIElementTypeAlert"):
                print(f"[Appium]: alert rilevato: '{alert.get('name')}'")
                buttons = alert.findall('.//XCUIElementTypeButton')
                alreadyClicked = False
                for button in buttons:
                    if button.get('name') in buttonsToAutomaticallyAccept:
                        print("[Appium]: clicco sul bottone " + button.get('name'))
                        appiumDriver.find_element(by=AppiumBy.NAME, value=button.get('name')).click()
                        alreadyClicked = True
                        break

                if not alreadyClicked:
                    i = random.randint(0, len(buttons) - 1)
                    print("[Appium]: clicco su " + buttons[i].get('name'))
                    appiumDriver.find_element(by=AppiumBy.NAME, value=buttons[i].get('name')).click()

            else:
                if statusBar := root.find(".//XCUIElementTypeStatusBar"):
                    statusBar.getparent().remove(statusBar)

                for element in root.iter():
                    if element.get('accessible') == 'true' and element.get('name') != 'None':
                        accessibleElements.append(element.get('name'))
                        # print(element.get('name'))

                i = random.randint(0, len(accessibleElements) - 1)
                print(f"[Appium]: interagisco con '{str(accessibleElements[i])}' ")
                interactedElement = appiumDriver.find_elements(by=AppiumBy.ID, value=accessibleElements[i])
                interactedElement[0].click()
                time.sleep(5)
                if appiumDriver.find_elements(by=AppiumBy.ID, value=accessibleElements[i]) != 0:
                    print("[Appium]: .click() non ha funzionato, torno indietro")
                    appiumDriver.back()

                accessibleElements.clear()
                print("==== INTERAZIONE COMPLETATA ====")
        elif appState == 3 or appState == 2:
            print("App in background, riporto in foreground...")
            appiumDriver.activate_app(bundleID)
        else:
            print("App non in esecuzione, il programma verrà chiuso!")
            sys.exit()


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

def installApp(appDir):
    print("installazione app...")
    # TODO


if __name__ == '__main__':
    print("lettura delle capabilities da file JSON...")
    desiredCaps, appName, udid, app = defineCaps()
    print("...lettura completata")

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
            installApp(app)
            print("## installazione completata ##")
            break

        if val == "n":
            break

    print("## esecuzione del test ##")
    appiumModuleProcess = Process(target=appiumModule, args=(desiredCaps, appName))
    appiumModuleProcess.start()
    strace.main(appName)
    appiumModuleProcess.join()
    print("## test terminato ##")
