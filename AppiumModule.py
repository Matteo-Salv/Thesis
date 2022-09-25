from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from appium.webdriver.common.touch_action import TouchAction
from lxml import etree as eT
from dataclasses import dataclass
import random
import sys
import time
import warnings

# necessario in quanto il metodo root.find() di lxml crea delle futurewarning
warnings.simplefilter(action='ignore', category=FutureWarning)

buttonsToAutomaticallyAccept = ['OK', 'ok', 'allow', 'Allow', 'Consentire']
elementsToIgnore = ['XCUIElementTypeNavigationBar', 'XCUIElementTypeStaticText', 'XCUIElementTypeTextView', 'XCUIElementTypeNavigationBar']
appiumDriver: webdriver
touchActions: TouchAction


@dataclass
class AccessibleElement:
    value: str
    isByName: bool


def interactWithTextField(field, root):
    print(f"[Appium]: Interacting with a text field...")
    field.send_keys("The answer is 42")
    if appiumDriver.is_keyboard_shown():
        # TODO: il click non sempre funziona, da testare su più app
        # necessario altrimenti Appium potrebbe non vedere la tastiera
        time.sleep(5)
        keyboard = root.find(".//XCUIElementTypeKeyboard")
        buttons = keyboard.findall('.//XCUIElementTypeButton')
        print(f"[Appium]: Interacting with '{buttons[len(buttons) - 1].get('name')}' on the keyboard")
        time.sleep(3)
        appiumDriver.find_element(by=AppiumBy.NAME, value=buttons[len(buttons) - 1].get('name')).click()


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
            # TODO: da testare, a volte si blocca dopo aver cliccato un tasto tra quelli da accettare in automatico

    if not alreadyClicked:
        i = random.randint(0, len(buttons) - 1)
        print("[Appium]: click on " + buttons[i].get('name'))
        button = appiumDriver.find_element(by=AppiumBy.NAME, value=buttons[i].get('name'))
        touchActions.tap(button).perform()


def interactWithSlider(slider):
    print(f"[Appium]: Interacting with a slider...")
    touchActions.tap(slider).perform()
    value = random.randint(0, 100)
    print(f"setting slider to value {value}%")
    if value == 100:
        slider.set_value(str(1))
    else:
        slider.set_value("0." + str(value))


def interactWithElement(element, root):
    if str(element.get_attribute("type")) == "XCUIElementTypeTextField":
        interactWithTextField(element, root)
    elif str(element.get_attribute("type")) == "XCUIElementTypeSlider":
        interactWithSlider(element)
    else:
        print(f"[Appium]: interacting with '{element.text}', "
              f"type '{element.get_attribute('type')}'")
        touchActions.tap(element).perform()


def startAppiumModule(desiredCaps, bundleID):
    previousRoot = None
    alreadyInteracted = False
    alreadyGoneBack = False
    accessibleElements = list()
    print("Appium module successfully started")
    print("[Appium]: connecting to the device...")
    global appiumDriver
    appiumDriver = webdriver.Remote('http://0.0.0.0:4723/wd/hub', desiredCaps)
    global touchActions
    touchActions = TouchAction(appiumDriver)
    print("[Appium]: ...connection completed!")
    time.sleep(5)

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
                alreadyInteracted = True

            # check if the keyboard is shown
            elif appiumDriver.is_keyboard_shown():
                if textFields := appiumDriver.find_elements(by=AppiumBy.XPATH, value='//XCUIElementTypeTextField'):
                    for textField in textFields:
                        interactWithTextField(textField, root)
                    alreadyInteracted = True
                else:
                    print(
                        "[Appium]: Something went wrong. The keyboard is shown but there are not Text Fields. Closing...")
                    sys.exit()

            elif not alreadyInteracted:
                # delete status bar
                if statusBar := root.find(".//XCUIElementTypeStatusBar"):
                    statusBar.getparent().remove(statusBar)

                # add potential iteractive elements
                for element in root.iter():
                    if element.get('accessible') == 'true' and element.get('enabled') == 'true' and element.get('type') not in elementsToIgnore:
                        if str(element.get('name')) != 'None':
                            accessibleElements.append(AccessibleElement(element.get('name'), True))
                        else:
                            accessibleElements.append(AccessibleElement(element.get('type'), False))
                        print(f"[Appium]: '{accessibleElements[len(accessibleElements)-1].value}', "
                              f"'{accessibleElements[len(accessibleElements)-1].isByName}'")

                # check if the previous interaction worked
                if previousRoot is not None and eT.tostring(previousRoot) == eT.tostring(root) and not alreadyGoneBack:
                    print("[Appium]: the previous interaction didn't work, going back...")
                    appiumDriver.back()
                    alreadyGoneBack = True

                else:
                    alreadyGoneBack = False
                    i = random.randint(0, len(accessibleElements) - 1)
                    print(f"[Appium]: Element '{accessibleElements[i].value}' selected")
                    if accessibleElements[i].isByName:
                        if interactedElement := appiumDriver.find_element(by=AppiumBy.ID, value=accessibleElements[i].value):
                            interactWithElement(interactedElement, root)
                        else:
                            print(f"[Appium]: Element '{accessibleElements[i].value}' not found!")
                    else:
                        if interactedElement := appiumDriver.find_elements(by=AppiumBy.CLASS_NAME, value=accessibleElements[i].value):
                            interacted = False
                            while not interacted and len(interactedElement) > 0:
                                k = random.randint(0, len(interactedElement) - 1)
                                if interactedElement[k].get_attribute('accessible') == 'true':
                                    interactWithElement(interactedElement[k], root)
                                    interacted = True
                                else:
                                    interactedElement.remove(interactedElement[k])
                        else:
                            print(f"[Appium]: Element {accessibleElements[i]} not found!")

                time.sleep(5)
                alreadyInteracted = False
                previousRoot = root
                accessibleElements.clear()
                print("==== INTERACTION COMPLETED ====")

        elif appState == 3 or appState == 2:
            print("[Appium]: app is running in background, going back in foreground...")
            appiumDriver.activate_app(bundleID)
        else:
            print("[Appium]: the app is not running, closing!")
            sys.exit()
