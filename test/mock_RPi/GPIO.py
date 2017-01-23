call_history = []
output_value = None

BOARD = 'BOARD'
BCM = 'BCM'
IN = 'IN'
OUT = 'OUT'
HIGH = 'HIGH'
LOW = 'LOW'
PUD_UP = 'PUD_UP'

def setmode(mode):
    call_history.append({'method': 'setmode', 'mode': mode})

def setup(pin, mode, pull_up_down=None):
    call_history.append({'method': 'setup', 'pin': pin, 'mode': mode, 'pull_up_down': pull_up_down})

def output(pin, value):
    call_history.append({'method': 'output', 'pin': pin, 'value': value})

def input(pin):
    call_history.append({'method': 'input', 'pin': pin})

    if output_value in [0,1]:
        return output_value
    if type(output_value) is dict and pin in output_value:
        return output_value[pin].pop(0)
    return 0

def cleanup():
    call_history.append({'method': 'cleanup'})
