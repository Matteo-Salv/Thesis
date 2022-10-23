from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from appium.webdriver.common.touch_action import TouchAction
from lxml import etree as eT
from dataclasses import dataclass
from datetime import datetime
import random
import sys
import time
import warnings

# necessario in quanto il metodo root.find() di lxml crea delle futurewarning
warnings.simplefilter(action='ignore', category=FutureWarning)


@dataclass
class AccessibleElement:
    value: str
    isByName: bool


class AppiumModule:
    def __init__(self):
        self.f = None
        self.alertButtonsToAccept = list()
        self.buttonsToIgnore = list()
        self.elementsToIgnore = ['XCUIElementTypeNavigationBar', 'XCUIElementTypeStaticText', 'XCUIElementTypeTextView',
                            'XCUIElementTypeNavigationBar']
        self.appiumDriver: webdriver
        self.touchActions: TouchAction


    def currentTime(self) -> str:
        now = datetime.now()
        return now.strftime("%H:%M:%S")

    def interactWithTextField(self, field):
        print(f"[Appium]: Interacting with a text field...")
        self.f.write(f"[Appium {self.currentTime()}]: Interacting with a text field\n")
        field.send_keys("The answer is 42")
        if self.appiumDriver.is_keyboard_shown():
            root: eT._Element = eT.XML(self.appiumDriver.page_source.encode())
            # necessario altrimenti Appium potrebbe non vedere la tastiera
            time.sleep(5)
            keyboard = root.find(".//XCUIElementTypeKeyboard")
            buttons = keyboard.findall('.//XCUIElementTypeButton')
            print(f"[Appium]: Interacting with '{buttons[len(buttons) - 1].get('name')}' on the keyboard")
            self.f.write(f"[Appium {self.currentTime()}]: Interacting with '{buttons[len(buttons) - 1].get('name')}' on the keyboard\n")
            time.sleep(3)
            self.appiumDriver.find_element(by=AppiumBy.NAME, value=buttons[len(buttons) - 1].get('name')).click()

    def interactWithAlert(self, alert, root):
        if textField := root.find(".//XCUIElementTypeTextField"):
            field = self.appiumDriver.find_element(by=AppiumBy.NAME, value=textField.get('name'))
            self.interactWithTextField(field)
        buttons = alert.findall('.//XCUIElementTypeButton')
        alreadyClicked = False
        for button in buttons:
            if button.get('name') in self.alertButtonsToAccept:
                print("[Appium]: click on the button " + button.get('name'))
                self.f.write(f"[Appium {self.currentTime()}]: click on the button {button.get('name')}\n")
                button = self.appiumDriver.find_element(by=AppiumBy.NAME, value=button.get('name'))
                self.touchActions.tap(button).perform()
                alreadyClicked = True
                break
                # TODO: da testare, a volte si blocca dopo aver cliccato un tasto tra quelli da accettare in automatico

        if not alreadyClicked:
            i = random.randint(0, len(buttons) - 1)
            print("[Appium]: click on " + buttons[i].get('name'))
            self.f.write(f"[Appium {self.currentTime()}]: click on {buttons[i].get('name')}\n")
            button = self.appiumDriver.find_element(by=AppiumBy.NAME, value=buttons[i].get('name'))
            self.touchActions.tap(button).perform()

    def interactWithSlider(self, slider):
        print(f"[Appium]: Interacting with a slider...")
        self.f.write(f"[Appium {self.currentTime()}]: Interacting with a slider...\n")
        self.touchActions.tap(slider).perform()
        value = random.randint(0, 100)
        print(f"setting slider to value {value}%")
        if value == 100:
            slider.set_value(str(1))
        else:
            slider.set_value("0." + str(value))

    def interactWithElement(self, element, root):
        if str(element.get_attribute("type")) == "XCUIElementTypeTextField":
            self.interactWithTextField(element)
        elif str(element.get_attribute("type")) == "XCUIElementTypeSlider":
            self.interactWithSlider(element)
        else:
            print(f"[Appium]: interacting with '{element.text}', "f"type '{element.get_attribute('type')}'")
            self.f.write(f"[Appium {self.currentTime()}]: interacting with '{element.text}', "f"type '{element.get_attribute('type')}'\n")
            self.touchActions.tap(element).perform()

    def startAppiumModule(self, desiredCaps, bundleID, alertButtonsToAccept: str, buttonsToIgnore: str):
        self.f = open("AppiumOutput.txt", "w")
        previousRoot = None
        alreadyInteracted = False
        alreadyGoneBack = False
        if alertButtonsToAccept != "":
            self.alertButtonsToAccept = alertButtonsToAccept.split(',')
        if buttonsToIgnore != "":
            self.buttonsToIgnore = buttonsToIgnore.split(',')
        accessibleElements = list()
        print("Appium module successfully started")
        print("[Appium]: connecting to the device...")
        self.f.write(f"[Appium {self.currentTime()}]: connecting to the device...\n")
        self.appiumDriver = webdriver.Remote('http://0.0.0.0:4723/wd/hub', desiredCaps)
        self.touchActions = TouchAction(self.appiumDriver)
        print("[Appium]: ...connection completed!")
        self.f.write(f"[Appium {self.currentTime()}]: ...connection completed!\n")
        time.sleep(5)

        while True:
            root: eT._Element = eT.XML(self.appiumDriver.page_source.encode())

            # 0 is not installed. 1 is not running. 2 is running in background or suspended.
            # 3 is running in background. 4 is running in foreground
            appState = self.appiumDriver.query_app_state(bundleID)
            if appState == 4:

                # alert found
                if alert := root.find(".//XCUIElementTypeAlert"):
                    print(f"[Appium]: alert found: '{alert.get('name')}'")
                    self.f.write(f"[Appium {self.currentTime()}]: alert found: '{alert.get('name')}'\n")
                    self.interactWithAlert(alert, root)
                    alreadyInteracted = True

                # check if the keyboard is shown
                elif self.appiumDriver.is_keyboard_shown():
                    if textFields := self.appiumDriver.find_elements(by=AppiumBy.XPATH,
                                                                     value='//XCUIElementTypeTextField'):
                        for textField in textFields:
                            self.interactWithTextField(textField)
                        alreadyInteracted = True
                    else:
                        print("[Appium]: Something went wrong. The keyboard is shown but there are not Text Fields. Closing...")
                        sys.exit()

                elif not alreadyInteracted:
                    # delete status bar
                    if statusBar := root.find(".//XCUIElementTypeStatusBar"):
                        statusBar.getparent().remove(statusBar)

                    # add potential iteractive elements
                    for element in root.iter():
                        if element.get('accessible') == 'true' and element.get('enabled') == 'true' and element.get(
                                'type') not in self.elementsToIgnore and element.get('name') not in self.buttonsToIgnore:
                            if str(element.get('name')) != 'None':
                                accessibleElements.append(AccessibleElement(element.get('name'), True))
                            else:
                                accessibleElements.append(AccessibleElement(element.get('type'), False))
                            print(f"[Appium]: '{accessibleElements[len(accessibleElements) - 1].value}', "
                                  f"'{accessibleElements[len(accessibleElements) - 1].isByName}'")

                    # check if the previous interaction worked
                    if previousRoot is not None and eT.tostring(previousRoot) == eT.tostring(
                            root) and not alreadyGoneBack:
                        print("[Appium]: the previous interaction didn't work, going back...")
                        self.f.write(f"[Appium {self.currentTime()}]: the previous interaction didn't work, going back...\n")
                        self.appiumDriver.back()
                        alreadyGoneBack = True

                    elif len(accessibleElements) != 0:
                        alreadyGoneBack = False
                        i = random.randint(0, len(accessibleElements) - 1)
                        print(f"[Appium]: Element '{accessibleElements[i].value}' selected")
                        if accessibleElements[i].isByName:
                            if interactedElement := self.appiumDriver.find_element(by=AppiumBy.ID,
                                                                                   value=accessibleElements[i].value):
                                self.interactWithElement(interactedElement, root)
                            else:
                                print(f"[Appium]: Element '{accessibleElements[i].value}' not found!")
                                self.f.write(f"[Appium {self.currentTime()}]: Element '{accessibleElements[i].value}' not found!\n")
                        else:
                            if interactedElement := self.appiumDriver.find_elements(by=AppiumBy.CLASS_NAME,
                                                                                    value=accessibleElements[i].value):
                                interacted = False
                                while not interacted and len(interactedElement) > 0:
                                    k = random.randint(0, len(interactedElement) - 1)
                                    if interactedElement[k].get_attribute('accessible') == 'true':
                                        self.interactWithElement(interactedElement[k], root)
                                        interacted = True
                                    else:
                                        interactedElement.remove(interactedElement[k])
                            else:
                                print(f"[Appium]: Element {accessibleElements[i]} not found!")
                                self.f.write(f"[Appium {self.currentTime()}]: Element {accessibleElements[i]} not found!\n")
                    else:
                        print("[Appium]: no accessible elements found!, going back to the previous view...")
                        self.f.write(f"[Appium {self.currentTime()}]: no accessible elements found!, going back to the previous view...\n")
                        self.appiumDriver.back()

                    previousRoot = root
                    accessibleElements.clear()
                alreadyInteracted = False
                print("==== INTERACTION COMPLETED ====")
                self.f.write(f"[Appium {self.currentTime()}]: ==== INTERACTION COMPLETED ====\n")
                # sleep che serve sia per sincronizzare l'interazione di appium che eventualmente permettere all'utente
                # di interagire manualmente con l'app prima della prossima interazione
                time.sleep(10)

            elif appState == 3 or appState == 2:
                print("[Appium]: app is running in background, going back in foreground...")
                self.f.write(f"[Appium {self.currentTime()}]: app is running in background, going back in foreground...\n")
                self.appiumDriver.activate_app(bundleID)
            else:
                print("[Appium]: the app is not running, closing!")
                sys.exit()
