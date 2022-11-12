var ThreadsFollowed = {};

function isThreadFollowed(tid) {
    if (ThreadsFollowed.tid) {
        return true;
    } else {
        return false;
    }
}

function FollowThread(tid) {
    ThreadsFollowed[tid] = true;
    console.log("[Strace]: [+] Following thread " + tid);
    //Frida Stalker on current thread
    Stalker.follow(tid, {
        transform: function (iterator) {
            //read the instruction
            const instruction = iterator.next();
            do {
                //search for supervisor call. .mnemonic is a parse method provided by Frida on the object returned from iterator.next()
                if (instruction.mnemonic === "svc") {
                    //this function send the current (thread) CPU context to onMatch, registers included
                    iterator.putCallout(onMatch);
                }
                iterator.keep();
            } while (iterator.next() !== null);

            function onMatch(context) {
                //from the current context extract the content of x16 register (which contains the syscall number)
                send(tid + ":" + context.x16.toInt32());
            }
        },
    });
}

function UnfollowThread(threadId) {
    if (!isThreadFollowed(threadId)) {
        return;
    }
    delete ThreadsFollowed[threadId];
    console.log("[Strace]: [+] Unfollowing thread " + threadId);
    Stalker.unfollow(threadId);
    Stalker.garbageCollect();
}

function ThreadStalker() {
    FollowThread(Process.getCurrentThreadId());
    //effettuo l'attach dell'export chiamato '_pthread_start' -> intercetto ogni creazione di un nuovo thread
    Interceptor.attach(Module.getExportByName(null, "_pthread_start"), {
        onEnter(args) {
            if (isThreadFollowed(this.threadId)) {
                return;
            }
            // console.log("strace, args[2]: " + args[2]);
            const functionAddress = args[2];
            Interceptor.attach(functionAddress, {
                onEnter(args) {
                    FollowThread(this.threadId);
                },
                onLeave(retVal) {
                    UnfollowThread(this.threadId);
                },
            });
        },
    });
}

ThreadStalker();
