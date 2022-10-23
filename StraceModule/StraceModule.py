from datetime import datetime
import os
import frida
import sys

class StraceModule:
    def __init__(self):
        with open(os.getcwd() + "/StraceModule/syscall.txt", "r") as f:
            raw_syscall_list = f.readlines()
        self.syscalls = [syscall.split(". ") for syscall in raw_syscall_list]
        self.syscalls = {syscall[0]: syscall[1] for syscall in self.syscalls}
        self.previousSyscall = ""
        self.previousThread_id = 0
        self.f_output = open("StraceOutput.txt", "w")
        self.session = None


    def currentTime(self) -> str:
        now = datetime.now()
        return now.strftime("%H:%M:%S")


    def on_message(self, message, _):
        # message[] viene utilizzato per leggere la stringa json inviata dalla funzione send in JS.
        thread_id, syscall_number = message["payload"].split(":")
        syscall_number = str(abs(int(syscall_number)))
        if syscall_number in self.syscalls.keys():
            if self.previousSyscall != self.syscalls[syscall_number] and self.previousThread_id != thread_id:
                print(f"[Strace {self.currentTime()}]: [thread {thread_id}]: {self.syscalls[syscall_number]}")
                self.f_output.write(f"[Strace {self.currentTime()}] [thread {thread_id}]: {self.syscalls[syscall_number]}\n")
                self.f_output.flush()
                self.previousSyscall = self.syscalls[syscall_number]
                self.previousThread_id = thread_id

#       else:
#           print(f"[{thread_id}]: Unknown({syscall_number})")


    def on_detached(self):
        sys.exit()


    def appIsAlreadyRunning(self, appName) -> bool:
        apps = device.enumerate_processes()
        for app in apps:
            if app.name == appName:
                return True
        return False


    def appConnection(self, appName) -> str:
        global device
        device = frida.get_usb_device()
        if self.appIsAlreadyRunning(appName):
            print("Error! App must be manually closed on the device! Please check and then run again!")
            return None
        appIdentifier: str = None
        apps = device.enumerate_applications()
        global pid
        for app in apps:
            if appName == app.name:
                appIdentifier: str = app.identifier
                pid = app.identifier
                break

        if appIdentifier is None:
            print(f"[strace]: Error! {appName} not found! Is it installed?")
            return None
        else:
            print("Strace module successfully started")
            pid = device.spawn([appIdentifier])
            print(f"[strace]: pid {pid}")
            self.f_output.write(f"[strace {self.currentTime()}]: pid {pid}\n")
            self.f_output.flush()
            self.session = device.attach(pid)
            self.session.on('detached', self.on_detached)
        print("App started!")
        return appIdentifier


    def startStraceModule(self) -> None:
        with open(os.getcwd() + "/StraceModule/tracer.js", "r") as f:
            tracer_source = f.read()
        script = self.session.create_script(tracer_source)
        script.load()
        script.on("message", self.on_message)
        device.resume(pid)
        sys.stdin.read()
