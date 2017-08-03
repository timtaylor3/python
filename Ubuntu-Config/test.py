from ctypes import *

if (windll.user32.MessageBoxA(0, "Click Yes or NO", "This is a Title", 4)) == 6:
	cdll.msvcrt.printf("Yes\n")
else:
	cdll.msvcrt.printf("No\n")
