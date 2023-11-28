import sys
import frida
import argparse
import subprocess
import shutil
import shlex


def on_message(message, data):
    print("[!] [Message] %s -> %s" % (message, data))


def main(pid=None, cmd=None, args=None, script=None):
    if (script == None):
        print("[!] Error: No script specified")
        return

    session = False
    print("[+] Waiting for process")
    while not session:
        if pid:
            try:
                session = frida.attach(int(pid))
            except frida.ProcessNotFoundError:
                print("[!] Unable to locate pid %d" % int(pid))
                sys.exit(1)
        else:
            try:
                session = frida.attach(cmd)
            except frida.ProcessNotFoundError as error:
                print("[!] %s" % error)
                print("[!] %s Attempting to spawn." % cmd)
                cmdArray = [shutil.which(cmd)]
                if (cmdArray == [None]):
                    print("[!] Unable to locate command %s" % cmd)
                    sys.exit(4)

                if (args):
                    cmdArray += shlex.split(args)
                proc = subprocess.Popen(cmdArray)
                try:
                    session = frida.attach(proc.pid)
                    if not session:
                        print("[!] failed to spawn %s" % cmd)
                        sys.exit(2)
                except Exception as error:
                    print("[!] Error: %s" % error)
                    sys.exit(3)
    print("[+] %s" % session)
    script = session.create_script(open("sqlite.js").read())

    script.on("message", on_message)
    script.load()
    input("[+] Press <Enter> at any time to detach from instrumented program.\n\n")
    session.detach()
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--pid", help="pid to attach to")
    group.add_argument("-c", "--cmd", help="The command to attach to or spawn")
    parser.add_argument("-a", "--args", help="The arguments for the cmd to spawn (optional)")
    parser.add_argument("-s", "--script", help="The Frida script to load")
    args = parser.parse_args()

    main(pid=args.pid, cmd=args.cmd, args=args.args, script=args.script)
