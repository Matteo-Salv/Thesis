import json
import os
import warnings
from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from lxml import etree as eT
import random
import time
import iOS_strace.strace as strace
from multiprocessing import Process, Value

# necessario in quanto il metodo root.find() di lxml crea delle futurewarning
warnings.simplefilter(action='ignore', category=FutureWarning)


def findElements(desired_caps, v):
    print("modulo Appium avviato con successo")
    appiumDriver = webdriver.Remote('http://0.0.0.0:4723/wd/hub', desired_caps)
    print("[Appium]: app avviata con successo")
    v.value = 1
    accessibleElements = list()
    while True:
        root: eT._Element = eT.XML(appiumDriver.page_source.encode())
        if alert := root.find(".//XCUIElementTypeAlert"):
            print(f"[Appium]: alert rilevato: '{alert.get('name')}', aggiorno la pagina sorgente")
            # TODO: trovare un modo per gestire gli alert non di sistema
            appiumDriver.switch_to.alert.accept()

        else:
            if statusBar := root.find(".//XCUIElementTypeStatusBar"):
                statusBar.getparent().remove(statusBar)

            for element in root.iter():
                if element.get('accessible') == 'true' and element.get('name') != 'None':
                    accessibleElements.append(element.get('name'))
                    print(element.get('name'))

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


def defineCaps():
    f = open("caps.json")
    data = json.load(f)

    desired_caps = dict(
        platformName='iOS',
        platformVersion=data["version"],
        deviceName=data["device"],
        automationName='xcuitest',
        udid=data["udid"],
        app=data["app"],
        wdaLaunchTimeout="120000"
        # autoAcceptAlerts="true"
    )

    return desired_caps, data["appName"], data["udid"]


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


if __name__ == '__main__':
    print("lettura delle capabilities da file JSON...")
    desiredCaps, appName, udid = defineCaps()
    print("...lettura completata")
    while True:
        val = input("Effettuare il resigning di WebDriverAgent? (y/n) (necessario dopo una settimana)")
        if val == "y":
            print("## avvio resigning ##")
            resignWDA(udid)
            print("## resigning completato ##")
            break

        if val == "n":
            break

    print("## esecuzione del test ##")
    v = Value('i', 0)
    findElementsProcess = Process(target=findElements, args=(desiredCaps, v,))
    findElementsProcess.start()
    straceProcess = Process(target=strace.main, args=(appName,))
    while True:
        if v.value == 1:
            straceProcess.start()
            break
    findElementsProcess.join()
    straceProcess.join()
    print("## test terminato ##")
