import datetime
import os
import frida
import sys

with open(os.getcwd() + "/StraceModule/syscall.txt", "r") as f:
    raw_syscall_list = f.readlines()

syscalls = [syscall.split(". ") for syscall in raw_syscall_list]
syscalls = {syscall[0]:syscall[1] for syscall in syscalls}
previousSyscall = ""
previousThread_id = 0

def on_message(message, _):
    global previousSyscall
    global previousThread_id
    # message[] viene utilizzato per leggere la stringa json inviata dalla funzione send in JS.
    thread_id, syscall_number = message["payload"].split(":")
    syscall_number = str(abs(int(syscall_number)))
    if syscall_number in syscalls.keys():
        now = datetime.datetime.now()
        if previousSyscall != syscalls[syscall_number] and previousThread_id != thread_id:
            print(f"[Strace]: [thread {thread_id}] {now.strftime('%H:%M:%S')}: {syscalls[syscall_number]}")
            previousSyscall = syscalls[syscall_number]
            previousThread_id = thread_id

#    else:
#        print(f"[{thread_id}]: Unknown({syscall_number})")


def on_detached():
    sys.exit()


def main(appName) -> None:
    print("modulo strace avviato con successo")
    device = frida.get_usb_device()
    apps = device.enumerate_applications()
    appIdentifier = None
    for app in apps:
        if appName == app.name:
            appIdentifier: str = app.identifier
            break

    if appIdentifier is None:
        print(f"[strace]: Errore! {appName} non trovata sul dispositivo! uscita...")
        sys.exit()
    pid = device.spawn([appIdentifier])
    print(f"[strace]: pid: {pid}")
    session = device.attach(pid)
    session.on('detached', on_detached)

    with open(os.getcwd() + "/StraceModule/tracer.js", "r") as f:
        tracer_source = f.read()

    script = session.create_script(tracer_source)
    script.load()
    script.on("message", on_message)
    device.resume(pid)
    sys.stdin.read()
