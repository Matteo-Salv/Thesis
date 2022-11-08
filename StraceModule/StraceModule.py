from datetime import datetime
import os
import frida
import sys


class StraceModule:
    def __init__(self):
        self.syscalls = None
        self.syscalls = None
        self.previousMessage = ""
        self.f_output = open("StraceOutput.txt", "w")
        self.session = None
        self.device = None
        self.pid = None

    def createSysCallsList(self, sysCallsFileName) -> bool:
        with open(os.getcwd() + "/SystemCalls/" + sysCallsFileName, "r") as f:
            raw_syscall_list = f.readlines()
        self.syscalls = [syscall.split(". ") for syscall in raw_syscall_list]
        self.syscalls = {syscall[0]: syscall[1] for syscall in self.syscalls}
        if len(self.syscalls) != 0:
            return True
        else:
            return False

    def writeOnFile(self, text: str):
        self.f_output.write(text)
        self.f_output.flush()

    def currentTime(self) -> str:
        now = datetime.now()
        return now.strftime("%H:%M:%S")

    def on_message(self, message, _):
        # message[] viene utilizzato per leggere la stringa json inviata dalla funzione send in JS.
        thread_id, syscall_number = message["payload"].split(":")
        syscall_number = str(abs(int(syscall_number)))
        thisMessage = f"[Strace {self.currentTime()}]: [thread {thread_id}]: {self.syscalls[syscall_number]}"
        if syscall_number in self.syscalls.keys() and self.previousMessage != thisMessage:
            print(thisMessage)
            self.writeOnFile(thisMessage)
            # necessary in order to ignore any eventually repeated message
            self.previousMessage = thisMessage

    def on_detached(self):
        sys.exit()

    def appIsAlreadyRunning(self, appName) -> bool:
        apps = self.device.enumerate_processes()
        for app in apps:
            if app.name == appName:
                return True
        return False

    def appConnection(self, appName) -> str:
        self.device = frida.get_usb_device()
        if self.appIsAlreadyRunning(appName):
            print("Error! App must be manually closed on the device! Please check and then run again!")
            return None
        appIdentifier: str = None
        apps = self.device.enumerate_applications()
        for app in apps:
            if appName == app.name:
                appIdentifier: str = app.identifier
                self.pid = app.identifier
                break
        if appIdentifier is None:
            print(f"[strace]: Error! {appName} not found! Is it installed?")
            return None
        else:
            print("Strace module successfully started")
            self.pid = self.device.spawn([appIdentifier])
            print(f"[strace]: pid {self.pid}")
            self.f_output.write(f"[strace {self.currentTime()}]: pid {self.pid}\n")
            self.f_output.flush()
            self.session = self.device.attach(self.pid)
            self.session.on('detached', self.on_detached)
        print("App started!")
        return appIdentifier

    def startStraceModule(self):
        with open(os.getcwd() + "/StraceModule/tracer.js", "r") as f:
            tracer_source = f.read()
        script = self.session.create_script(tracer_source)
        script.load()
        script.on("message", self.on_message)
        self.device.resume(self.pid)
        sys.stdin.read()
