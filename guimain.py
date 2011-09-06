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
# contains all of the code for the case creation UI and event handlers

import exception_handler

import sys, os, stat, time

# If we're in a pyinstaller executable, from volatility
if hasattr(sys, "frozen"):
    try:
        import iu, _mountzlib
        mei = os.path.abspath(os.environ["_MEIPASS2"])
        sys.path.append(mei)
        os.environ['PATH'] = mei + ";" + os.environ['PATH']
    except ImportError:
        pass


from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

from uifiles.reglive_ui import Ui_MainWindow
import acquire_files

guidrawn = 0

class regDecoderLiveGUI(QMainWindow, Ui_MainWindow):

    def __init__(self, app, parent =  None):
        
        # setup GUI
        QMainWindow.__init__(self, parent)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.app = app
        
        self.connect(self.browsePushButton, SIGNAL("clicked()"), self.outputDirBrowse)  

        self.connect(self.acquireFilesPushButton, SIGNAL("clicked()"), self.acquireFiles)        

    def outputDirBrowse(self):

        directory = QFileDialog.getExistingDirectory(parent=self, caption="Choose Case Save Directory")
        self.outputDirectoryLineEdit.setText(directory)

    # gets input from the GUI and sends to acquire_files, switches to results label
    def acquireFiles(self):

        compDesc  = unicode(self.compDescLineEdit.text())

        if compDesc == "":
            self.msgBox("No computer descrption was entered")
            return

        directory = unicode(self.outputDirectoryLineEdit.text())
       
        if not self.check_directory(directory):
            return
              
        acquire_current = self.currentFilesCheckBox.isChecked()

        acquire_backups = self.backupFilesCheckBox.isChecked()

        if not acquire_current and not acquire_backups:
            self.msgBox("Both acquire current and acquire backups were unchecked. Cannot proceed")
            return

        self.stackedWidget.setCurrentIndex(1)
            
        aq = acquire_files.acquire_files(directory, acquire_current, acquire_backups, compDesc, self)
        ret = aq.acquire_files()
        if ret == False:
            self.stackedWidget.setCurrentIndex(0)
            return ret

        # write out log file
        fd = open(os.path.join(directory, "logfile.txt"), "w")

        files = "\n".join([f for f in aq.added_files])
        runtime = time.strftime('%Y/%m/%d %H:%M:%S')
        cur  = ["No", "Yes"][acquire_current]
        back = ["No", "Yes"][acquire_backups]
        
        logdata = "Computer Descrption: %s\nCurrent Files Acquired: %s\nBackup  Files Acquired: %s\nAcquisition Time:       %s\nAcquired Files:\n%s\n" % \
                    (compDesc, cur, back, runtime , files)
                  
        fd.write(logdata)

        fd.close() 
        
        return True

    def check_directory(self, directory):

        ret = 0
        good = 0

        try:
            mode = os.stat(directory)[stat.ST_MODE]
            good = 1
        except:
            self.msgBox("Specified Directory Does not Exist")

        if good:
            if not mode & stat.S_IWUSR:
                self.msgBox("Unable to write to specific directory")
            
            elif os.listdir(directory):
                self.msgBox("Non-empty directory specificied. Pleaes choose another.")                
            
            else:
                ret = 1
            
        return ret

    def msgBox(self, msg):

        QMessageBox.critical(self, "Error", msg)

def main():

    app    = QApplication(sys.argv)

    window = regDecoderLiveGUI(app)

    window.showMaximized()

    app.exec_()

if __name__ == "__main__":
    main()


