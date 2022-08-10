import json
import os

from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
import xml.etree.ElementTree as eT
import random
import time
import iOS_strace.strace as strace
from multiprocessing import Process, Value


def findElements(desired_caps, v):
    print("modulo findElements avviato con successo")
    appiumDriver = webdriver.Remote('http://0.0.0.0:4723/wd/hub', desired_caps)
    v.value = 1
    accessibleElements = list()
    while True:
        root = eT.fromstring(appiumDriver.page_source)
        for element in root.iter():
            if element.get('accessible') == 'true' and element.get('name') != 'none':
                accessibleElements.append(element.get('name'))
                # print(element.get('name'))

        # print("tutti gli elementi interagibili della view attuale trovati.")
        # print("scelta randomica dell'elemento da cliccare...")
        i = random.randint(0, len(accessibleElements) - 1)
        print("interagisco con " + accessibleElements[i])
        interactedElement = appiumDriver.find_elements(by=AppiumBy.ID, value=accessibleElements[i])
        interactedElement[0].click()
        time.sleep(3)
        if appiumDriver.find_elements(by=AppiumBy.ID, value=accessibleElements[i]) != 0:
            print(".click() non ha funzionato, torno indietro")
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
    )

    return desired_caps, data["appName"]


def resignWDA():
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
              "-destination 'id=c5b7903056d30974db4cc14eb07617196735dc75' "
              "-allowProvisioningUpdates test")
    os.chdir(currentDir)
    print("test e resigning completato!")


if __name__ == '__main__':
    print("Test eseguibile solo su dispositivi fisici")
    while True:
        val = input("Effettuare il resigning di WebDriverAgent? (y/n) (necessario dopo una settimana)")
        if val == "y":
            resignWDA()
            break

        if val == "n":
            break

    print("lettura delle capabilities da file JSON ed avvio app...")
    desiredCaps, appName = defineCaps()
    print("...avvio completato! Esecuzione dei moduli...")
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
