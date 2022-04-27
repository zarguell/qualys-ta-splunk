# -*- coding: utf-8 -*-
__author__ = "Qualys, Inc"
__version__ = "1.0"

'''Imports'''
import os

#default values
code_directory_path = "../bin/"


os.system("find "+ code_directory_path +" -type f -type f -not -iname \"*.pyc\" -exec sha256sum {} \;" )
    
