import frida
from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from lxml import etree as eT
import random
import sys
import time
import warnings

# necessario in quanto il metodo root.find() di lxml crea delle futurewarning
warnings.simplefilter(action='ignore', category=FutureWarning)

buttonsToAutomaticallyAccept = ['OK', 'ok', 'allow', 'Allow', 'Consentire']


def appiumModule(desiredCaps, appName):

    print("Appium module successfully started")
    print("[Appium]: connecting to the app...")
    appiumDriver = webdriver.Remote('http://0.0.0.0:4723/wd/hub', desiredCaps)
    device = frida.get_usb_device()
    apps = device.enumerate_applications()
    time.sleep(3)
    bundleID = None
    for app in apps:
        if appName == app.name:
            bundleID = app.identifier
            break

    if bundleID is None:
        print(f"[Appium]: Error! {appName} not found on the device! exit...")
        sys.exit()

    print("[Appium]: ...connection completed!")
    accessibleElements = list()
    previousAccessibleElements = list()
    while True:
        root: eT._Element = eT.XML(appiumDriver.page_source.encode())

        # 0 is not installed. 1 is not running. 2 is running in background or suspended.
        # 3 is running in background. 4 is running in foreground
        appState = appiumDriver.query_app_state(bundleID)
        if appState == 4:
            if alert := root.find(".//XCUIElementTypeAlert"):
                print(f"[Appium]: alert found: '{alert.get('name')}'")
                buttons = alert.findall('.//XCUIElementTypeButton')
                alreadyClicked = False
                for button in buttons:
                    if button.get('name') in buttonsToAutomaticallyAccept:
                        print("[Appium]: click on the button " + button.get('name'))
                        appiumDriver.find_element(by=AppiumBy.NAME, value=button.get('name')).click()
                        alreadyClicked = True
                        break

                if not alreadyClicked:
                    i = random.randint(0, len(buttons) - 1)
                    print("[Appium]: click on " + buttons[i].get('name'))
                    appiumDriver.find_element(by=AppiumBy.NAME, value=buttons[i].get('name')).click()

            else:
                if statusBar := root.find(".//XCUIElementTypeStatusBar"):
                    statusBar.getparent().remove(statusBar)

                for element in root.iter():
                    if element.get('accessible') == 'true' and element.get('name') != 'None':
                        accessibleElements.append(element.get('name'))
                        # print(f"[Appium]: {element.get('name')}")
                if accessibleElements == previousAccessibleElements and len(previousAccessibleElements) != 0:
                    print("[Appium]: the previous interaction didn't work, going back...")
                    appiumDriver.back()
                else:
                    i = random.randint(0, len(accessibleElements) - 1)
                    if interactedElement := appiumDriver.find_elements(by=AppiumBy.ID,
                                                                               value=accessibleElements[i]):
                        print(f"[Appium]: interacting with '{interactedElement[0].text}' ")
                        interactedElement[0].click()
                    else:
                        print(f"Element {accessibleElements[i]} not found!")
                    # print("interactedElement: " + interactedElement[0].text)

                    previousAccessibleElements.clear()
                    for el in accessibleElements:
                        previousAccessibleElements.append(el)

                    accessibleElements.clear()
                    print("==== INTERACTION COMPLETED ====")

                time.sleep(5)

        elif appState == 3 or appState == 2:
            print("[Appium]: app is running in background, going back in foreground...")
            appiumDriver.activate_app(bundleID)
        else:
            print("[Appium]: the app is not running, closing!")
            sys.exit()
