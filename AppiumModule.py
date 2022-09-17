import frida
from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from appium.webdriver.common.touch_action import TouchAction
from lxml import etree as eT
import random
import sys
import time
import warnings

# necessario in quanto il metodo root.find() di lxml crea delle futurewarning
warnings.simplefilter(action='ignore', category=FutureWarning)

buttonsToAutomaticallyAccept = ['OK', 'ok', 'allow', 'Allow', 'Consentire']
elementsToIgnore = ['XCUIElementTypeNavigationBar', 'XCUIElementTypeStaticText']
appiumDriver: webdriver
touchActions: TouchAction


def interactWithTextField(field, root):
    print(f"[Appium]: Interacting with a text field...")
    field.send_keys("The answer is 42")
    if appiumDriver.is_keyboard_shown():
        # TODO: il click non sempre funziona, da testare su più app
        keyboard = root.find(".//XCUIElementTypeKeyboard")
        buttons = keyboard.findall('.//XCUIElementTypeButton')
        print(f"[Appium]: Interacting with '{buttons[len(buttons)-1].get('name')}' on the keyboard")
        time.sleep(3)
        appiumDriver.find_element(by=AppiumBy.NAME, value=buttons[len(buttons)-1].get('name')).click()


def interactWithAlert(alert, root):
    if textField := root.find(".//XCUIElementTypeTextField"):
        field = appiumDriver.find_element(by=AppiumBy.NAME, value=textField.get('name'))
        interactWithTextField(field, root)
    buttons = alert.findall('.//XCUIElementTypeButton')
    alreadyClicked = False
    for button in buttons:
        if button.get('name') in buttonsToAutomaticallyAccept:
            print("[Appium]: click on the button " + button.get('name'))
            button = appiumDriver.find_element(by=AppiumBy.NAME, value=button.get('name'))
            touchActions.tap(button).perform()
            alreadyClicked = True
            break

    if not alreadyClicked:
        i = random.randint(0, len(buttons) - 1)
        print("[Appium]: click on " + buttons[i].get('name'))
        button = appiumDriver.find_element(by=AppiumBy.NAME, value=buttons[i].get('name'))
        touchActions.tap(button).perform()


def startAppiumModule(desiredCaps, bundleID):
    print("Appium module successfully started")
    print("[Appium]: connecting to the device...")
    global appiumDriver
    appiumDriver = webdriver.Remote('http://0.0.0.0:4723/wd/hub', desiredCaps)
    global touchActions
    touchActions = TouchAction(appiumDriver)
    print("[Appium]: ...connection completed!")
    print("[Appium]: waiting to synchronize with the app...")
    time.sleep(15)
    print("[Appium]: ...synchronization completed!")


    accessibleElements = list()
    previousAccessibleElements = list()

    while True:
        root: eT._Element = eT.XML(appiumDriver.page_source.encode())

        # 0 is not installed. 1 is not running. 2 is running in background or suspended.
        # 3 is running in background. 4 is running in foreground
        appState = appiumDriver.query_app_state(bundleID)
        if appState == 4:
            # alert found
            if alert := root.find(".//XCUIElementTypeAlert"):
                print(f"[Appium]: alert found: '{alert.get('name')}'")
                interactWithAlert(alert, root)

            else:
                # delete status bar
                if statusBar := root.find(".//XCUIElementTypeStatusBar"):
                    statusBar.getparent().remove(statusBar)

                # add potential iteractive elements
                for element in root.iter():
                    if element.get('accessible') == 'true' and str(element.get('name')) != "None" and element.get('type') not in elementsToIgnore:
                        accessibleElements.append(element.get('name'))
                        print(f"[Appium]: '{element.get('name')}'")

                if accessibleElements == previousAccessibleElements and len(previousAccessibleElements) != 0:
                    print("[Appium]: the previous interaction didn't work, going back...")
                    previousAccessibleElements.clear()
                    appiumDriver.back()
                else:
                    i = random.randint(0, len(accessibleElements) - 1)
                    if interactedElement := appiumDriver.find_elements(by=AppiumBy.ID, value=accessibleElements[i]):
                        if str(interactedElement[0].get_attribute("type")) == "XCUIElementTypeTextField":
                            interactWithTextField(accessibleElements[i], root)

                        if appiumDriver.is_keyboard_shown():
                            textField = appiumDriver.find_element(by=AppiumBy.XPATH, value='//XCUIElementTypeTextField')
                            interactWithTextField(textField, root)
                        # TODO: aggiungere caso in cui si ha uno slider come funzione
                        else:
                            print(f"[Appium]: interacting with '{interactedElement[0].text}', "
                                  f"type '{interactedElement[0].get_attribute('type')}'")
                            touchActions.tap(interactedElement[0]).perform()

                    else:
                        print(f"[Appium]: Element {accessibleElements[i]} not found!")
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
