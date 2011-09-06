#
# Registry Decoder
# Copyright (c) 2011 Digital Forensics Solutions, LLC
#
# Contact email:  registrydecoder@digitalforensicssolutions.com
#
# Authors:
# Andrew Case       - andrew@digitalforensicssolutions.com
# Lodovico Marziale - vico@digitalforensicssolutions.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#
import sys, os, time, cStringIO, traceback

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

from error_classes import *

# taken from ERIC IDE since QT does not throw exceptions internally
def excepthook(excType, excValue, tracebackobj):

    if excType == MsgBoxError:
        errorbox = QMessageBox()
        errorbox.setWindowTitle(str("Registry Decoder"))
        errorbox.setText(str(excValue))
        errorbox.exec_()
        return
 
    dirname = os.getcwd()
    logfilename = os.path.join(dirname, "registry-decoder-error.txt")

    separator = "-" * 80

    notice = "An error has occurred and the details have been written to %s. Please send this file to registrydecoder@digdeeply.com so that we may address the issue." % (logfilename)
    
    timeString = time.strftime("%Y-%m-%d, %H:%M:%S")
        
    tbinfofile = cStringIO.StringIO()
    traceback.print_tb(tracebackobj, None, tbinfofile)
    tbinfofile.seek(0)
    tbinfo = tbinfofile.read()

    errmsg = '%s: \n%s' % (str(excType), str(excValue))

    sections = [separator, timeString, separator, errmsg, separator, tbinfo]

    msg = '\n'.join(sections)
    try:
        logfile = open(logfilename, "a+")
        logfile.write(msg)
        logfile.close()

    except IOError:
        pass

    try:
        errorbox = QMessageBox()
        errorbox.setText(str(notice))
        errorbox.exec_()
    except:
        print "Unable to create error message box. Error must have been hit early on. Please see registry-decoder-error.txt for error information"
        
    sys.exit(1)

sys.excepthook = excepthook