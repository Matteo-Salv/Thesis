import json
import os
import signal
import time
from dataclasses import dataclass
import StraceModule.StraceModule as sm
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
    sysCallsFile: str
    wdaDir: str
    timeout: int

    def __post_init__(self):
        if self.wdaDir is None:
            self.wdaDir = ""
        if self.alertButtonsToAccept is None:
            self.alertButtonsToAccept = ""
        if self.buttonsToIgnore is None:
            self.buttonsToIgnore = ""
        if self.app is None:
            self.app = ""
        if self.timeout is None:
            self.timeout = 600 # 10 mins


def resignWDA(udid, wdaDir):
    print("warning: during the WebDriverAgent installation process it may be necessary to go to 'settings > general > "
          "profile and device management' and then authorize the corresponding 'Apple Development' profile with which "
          "the app was previously signed")
    time.sleep(3)
    print("starting resigning...")
    currentDir = os.getcwd()
    os.chdir(wdaDir)
    os.system("xcodebuild "
              "-quiet "
              "-project WebDriverAgent.xcodeproj "
              "-scheme WebDriverAgentRunner "
              f"-destination 'id={udid}' "
              "-allowProvisioningUpdates")
    os.chdir(currentDir)


def timeout(timeout):
    start_time = time.time()
    while time.time() - start_time < timeout:
        time.sleep(1)
    print("timeout reached!")
    print("closing...")
    os.kill(os.getppid(), signal.SIGTERM)



def readJson():
    f = open("caps.json")
    data: dict = json.load(f)
    mandatoryOptions = ["version", "device", "udid", "appName", "systemCallsListFile"]
    notMandatoryOptions = ["app", "alertButtonsToAccept", "buttonsToIgnore", "wdaDir"]

    if all(elem in data for elem in mandatoryOptions):
        for notMandatoryOption in notMandatoryOptions:
            if notMandatoryOption not in data:
                data[notMandatoryOption] = None
        desired_caps = dict(
            platformName='iOS',
            platformVersion=data["version"],
            deviceName=data["device"],
            automationName='xcuitest',
            udid=data["udid"],
            # wdaLaunchTimeout="120000",
            noReset="true"
        )
        return jsonElements(desired_caps, data["appName"], data["udid"], data["app"], data["alertButtonsToAccept"],
                            data["buttonsToIgnore"], data["systemCallsListFile"], data["wdaDir"], data["timeout"])
    else:
        print("error! missing mandatory arguments inside caps.json! Follow the instruction!")
        return None


def installApp(appDir, udid):
    print("warning: during the installation process it may be necessary to go to 'settings > general > "
          "profile and device management' and then authorize the corresponding 'Apple Development' profile with which "
          "the app was previously signed")
    os.system(f"ios-deploy -i {udid} -b '{appDir}'")
    time.sleep(3)


if __name__ == '__main__':
    if readJson() is not None:
        jsonVals = readJson()

        if jsonVals.app != "":
            while True:
                val = input("do you want to install the app? (y/n)")
                if val == "y":
                    print("## starting installation ##")
                    installApp(jsonVals.app, jsonVals.udid)
                    print("## installation completed ##")
                    break

                elif val == "n":
                    break
        else:
            print("-- directory to .app or .ipa ('app' option) empty or missing in the configuration file. Skipping installation phase")

        if jsonVals.wdaDir != "":
            while True:
                val = input("do you want to resign the WebDriverAgent [WDA] App? (y/n) [necessary only if Appium has some issues about WDA connection/installation]:")
                # val = "n"

                if val == "y":
                    print("## starting resign ##")
                    resignWDA(jsonVals.udid, jsonVals.wdaDir)
                    print("## resign completed ##")
                    break

                if val == "n":
                    break
        else:
            print("-- wda directory ('wdaDir' option) empty or missing in the configuration file, skipping WDA installation")

        if jsonVals.alertButtonsToAccept == "":
            print("-- buttons to automatically accept inside an alert ('alertButtonsToAccept' option), empty or missing in the configuration file."
                  "the buttons inside an alert will be randomly selected")

        if jsonVals.buttonsToIgnore == "":
            print("-- buttons to ignore ('buttonsToIgnore' option empty or missing in the configuration file."
                  "every button inside the app could be potentially selected")

        print(f"## starting test, timeout: {jsonVals.timeout}s ##")
        straceModule = sm.StraceModule()
        appIdentifier = straceModule.appConnection(jsonVals.appName)
        appiumModule = am.AppiumModule()
        if appIdentifier is not None and straceModule.createSysCallsList(jsonVals.sysCallsFile):
            appiumModuleProcess = Process(target=appiumModule.startAppiumModule,
                                          args=(jsonVals.desiredCaps, appIdentifier, jsonVals.alertButtonsToAccept,
                                                jsonVals.buttonsToIgnore))
            timeoutProcess = Process(target=timeout, args=(jsonVals.timeout,))
            appiumModuleProcess.start()
            timeoutProcess.start()
            straceModule.startStraceModule()
            appiumModuleProcess.terminate()
            appiumModuleProcess.join()
            timeoutProcess.join()
            print("closing project")
    else:
        print("closing...")

