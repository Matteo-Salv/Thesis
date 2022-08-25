import datetime
import os
import frida
import sys

with open(os.getcwd() + "/iOS_strace/syscall.txt", "r") as f:
    raw_syscall_list = f.readlines()

syscalls = [syscall.split(". ") for syscall in raw_syscall_list]
syscalls = {syscall[0]:syscall[1] for syscall in syscalls}


def on_message(message, _):
    # message[] viene utilizzato per leggere la stringa json inviata dalla funzione send in JS.
    thread_id, syscall_number = message["payload"].split(":")
    syscall_number = str(abs(int(syscall_number)))
    if syscall_number in syscalls.keys():
        now = datetime.datetime.now()
        print(f"[Strace]: [thread {thread_id}] {now.strftime('%H:%M:%S')}: {syscalls[syscall_number]}")
#    else:
#        print(f"[{thread_id}]: Unknown({syscall_number})")


def on_detached():
    sys.exit()


def main(pid, bundleID) -> None:
    print("modulo strace avviato con successo")
    device = frida.get_usb_device()
    session = device.attach(pid)
    session.on('detached', on_detached)
    print(f"[Strace]: attach al processo '{bundleID}' con PID {str(pid)} effettuato con successo")

    with open(os.getcwd() + "/iOS_strace/tracer.js", "r") as f:
        tracer_source = f.read()

    script = session.create_script(tracer_source)
    script.load()
    script.on("message", on_message)
    device.resume(pid)
    sys.stdin.read()
