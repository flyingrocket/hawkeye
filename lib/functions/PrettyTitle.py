#! /usr/bin/env python3

def pretty_title(string, type = 'h2'):
    string = ' {} '.format(string)

    if type == 'h1':
        symbol = '$'
        width = 80
    elif type == 'h2':
        symbol = '_'
        width = 80
    elif type == 'h3':
        symbol = '_'
        width = 60

    return string.center(width, symbol)

