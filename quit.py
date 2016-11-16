import sys


def quit(logger, userinput):
    if userinput.lower() == 'quit':
        logger.critical('Exiting program - user entered "quit" in a prompt.')
        sys.exit()
