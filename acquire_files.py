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
import sys, os, copy, sqlite3, wmi, win32com.client, shutil, win32file, re, time

from error_classes import *

class acquire_files:

    def __init__(self, output_directory, acquire_current, acquire_backups, compdesc, gui=None):
    
        self.added_files = []

        self.output_directory = output_directory
        self.acquire_current  = acquire_current
        self.acquire_backups  = acquire_backups
        self.gui = gui
        self.compdesc = compdesc
        
        self.regfile_ctr = 0
        self.img_ctr     = 0
        
        self.store_dir = os.path.join(output_directory, "registryfiles")

        # this makes testing easier to avoid exception        
        try:
            os.mkdir(self.store_dir)
        except Exception, e:
            pass

        self.db_ops(output_directory)    
    
    def connect_db(self, directory, db_name):

        dbname = os.path.join(directory, db_name)
        conn = sqlite3.connect(dbname)
        cursor = conn.cursor()

        return (conn, cursor)
      
    def db_ops(self, case_dir):
 
        (self.conn, self.cursor) = self.connect_db(self.store_dir, "acquire_files.db")
        
        self.cursor.execute("select sql from sqlite_master where type='table' and name=?", ["evidence_sources"])
       
        # need to iniitalize the table of files
        # nothing to do if already created
        if not self.cursor.fetchall():
            
            tables = ["evidence_sources (filename text,   id integer primary key asc)",
                      "file_groups      (group_name text, evidence_file_id int, id integer primary key asc)",
                      "registry_files   (filename text,  mtime text, group_id int, file_id int, id integer primary key asc)",
                     ]
    
            for table in tables:
                self.cursor.execute("create table " + table)
                
            self.conn.commit()

    # enforces unique group_name and evidence_id pairs
    def group_id(self, group_name):

        ''' 
        there has to be a better way to do this
        but "insert or replace" changes the auto increment id
        '''

        evi_id = self.evidence_id

        self.cursor.execute("select id from file_groups where group_name=? and evidence_file_id=?", [group_name, evi_id])

        res = self.cursor.fetchone()
        
        # group doesn't exist for evidence file
        if not res:
            self.cursor.execute("insert into file_groups (group_name, evidence_file_id) values (?,?)", [group_name, evi_id])
            ret_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]
        
        else:
            ret_id = res[0]

        return ret_id

    def insert_reg_file(self, group_name, file_name, mtime):

        gid = self.group_id(group_name)
        file_id = self.regfile_ctr

        self.cursor.execute("insert into registry_files (filename, group_id, file_id, mtime) values (?,?,?,?)", [file_name, gid, file_id, mtime])

        self.regfile_ctr = self.regfile_ctr + 1
        
    def grab_file(self, group_name, directory, fname, realname=""):

        srcfile  = os.path.join(directory, fname)
        destfile = os.path.join(self.store_dir, "%d" % self.regfile_ctr)
        
        try:
            mtime = os.path.getmtime(srcfile)
        except:
            print "directory broke: %s" % directory
            print os.listdir(directory)

        shutil.copy(srcfile, destfile)
        
        if realname:
            fname = realname

        # put info into database
        self.insert_reg_file(group_name, fname, mtime) 
    
        self.added_files.append(srcfile)

    # grabs each registry file from an RP###/snapshot directory
    def parse_rp_folder(self, directory, group_name):
        
        # walk the snaphsot dir / it may not exist
        for root, dirs, files in os.walk(directory):

            for fname in files:
            
                if fname.startswith("_REGISTRY_MACHINE"):
                    self.grab_file(group_name, directory, fname)
                    
                elif fname.startswith("_REGISTRY_USER"):
                
                    # kludge for now... RPs will get updated to know live/ntuser if people care
                    if group_name == "CORE":
                        group_name = "NTUSER"
                        
                    self.grab_file(group_name, directory, fname)
                    self.refreshgui()
                    
    # parse RP structure
    def parse_system_restore(self, path, idx, group_name):

        elements = [path, "RP%d" % idx, "snapshot"]
        
        snappath = os.path.join(*elements)
                    
        self.parse_rp_folder(snappath, group_name)

    def handle_sys_restore(self, idx, group_name):

        startdir = r"\System Volume Information"
        
        # this will hit restore files for XP
        for root,dirs,files in os.walk(startdir):
            
            for dirname in dirs:
                if dirname.startswith("_restore{"):
                    path = os.path.join(startdir, dirname)
                    self.parse_system_restore(path, idx, group_name)
                    self.refreshgui()

    def acquire_backup_files(self, idxs):

        for idx in idxs:
            self.handle_sys_restore(idx, "RP%d" % idx)
        
    # get the active core & user registry files
    def acquire_active_files(self, current_idx):

        self.handle_sys_restore(current_idx, "CORE")
        
    def updateLabel(self, msg):
    
        if self.gui:
            self.gui.resultsLabel.setText(msg)
            self.refreshgui()
    
    def refreshgui(self):

        if self.gui:
            self.gui.update()
            self.gui.app.processEvents()
            self.gui.update()
            self.gui.app.processEvents()
        
    def set_system_restore_point(self):

        wmiobj = win32com.client.GetObject (r"winmgmts:{impersonationLevel=impersonate}!root/default:SystemRestore")
        sysRestore = wmi._wmi_object (wmiobj)
        
        methods = sysRestore.Methods_("CreateRestorePoint")
        params  = methods.InParameters
        
        params.Properties_.Item('Description').Value      = "Registry Decoder Restore Point"
        params.Properties_.Item('RestorePointType').Value = 0
        params.Properties_.Item('EventType').Value        = 100
        
        try:
            retval = sysRestore.ExecMethod_("CreateRestorePoint", params)
        except Exception, e:
            self.gui.msgBox("Unable to create a System Restore Point. Please check that you are running as administrator and that this computer has System Restore Point enabled.")
            return False
                
        ret = retval.Properties_.Item('ReturnValue').Value
                
        if ret != 0:
            self.gui.msgBox("Unable to create a System Restore Point. Please check that you are running as administrator and that this computer has System Restore Point enabled.")
            return False
            
        return True
                         
    def get_shadows(self):
    
        ret = []
        
        wmiobj = win32com.client.GetObject ("winmgmts:")        
        insts = wmiobj.InstancesOf("Win32_ShadowCopy")
        
        # there has to be a better way to check if the instancesOf returned valid data...
        try:
            len(insts)
        except:
            return ret
        
        for inst in insts:
            ret.append(inst.DeviceObject)
      
        return ret
      
    # this gets the directory to make the symbolic link in
    def get_vss_dir(self, shadow, i=0):
    
        vssfolder = r"\registrydecodervss%d" % i

        try:
            win32file.CreateSymbolicLink(vssfolder, shadow, 1)
        except Exception, e:
            #print "Exception: %s" % str(e)
            vssfolder = self.get_vss_dir(shadow, i + 1)
            
        return vssfolder
        
    def get_core_files_vss(self, directory, group_name):
    
        corefiles = ["SAM", "SECURITY", "SYSTEM", "SOFTWARE", "DEFAULT"]

        coreelements = [directory, "windows", "system32", "config"]

        corepath = os.path.join(*coreelements)

        for fname in corefiles:
                   
            self.grab_file(group_name, corepath, fname)
            self.refreshgui()
            
    def get_user_files_vss(self, shadow, group_name):
    
        userspath = os.path.join(shadow, "Users")
        
        for username in os.listdir(userspath):
        
            # path to a specific user
            ntpath = os.path.join(userspath, username)
            fpath  = os.path.join(ntpath, "ntuser.dat")
                
            if os.path.exists(fpath):
                self.grab_file(group_name, ntpath, "ntuser.dat", username)
                self.refreshgui()
                    
    def get_vss_reg_files(self, shadow, linkdir, active):
    
        if active:
            group_name = "CORE"
        else:
            # this gets the number of the copy 
            group_name = "VSS" + (re.match("\D+(\d+)", shadow).groups()[0])
        
        self.refreshgui()
        self.get_core_files_vss(linkdir, group_name)
        self.refreshgui()
        
        if active:
            group_name = "NTUSER"
        
        self.refreshgui()      
        self.get_user_files_vss(linkdir, group_name)
        self.refreshgui()
        
    def acquire_active_files_vss(self, shadow, active=1):
    
        # this is where the 'shadow' is mounted
        linkdir = self.get_vss_dir(shadow)

        self.refreshgui()
        self.get_vss_reg_files(shadow, linkdir, active)
        self.refreshgui()
        
        win32file.RemoveDirectory(linkdir)
      
    def acquire_backup_files_vss(self, shadows):
            
        for shadow in shadows:
            
            self.acquire_active_files_vss(shadow, 0)
            self.refreshgui()
      
    def get_vss(self, current):
    
        # this gets the path to every active shadow thing
        ret = self.get_shadows()
            
        if ret != []:
        
            if current:
                ret1 = ret[-1]
                ret  = ret[:-1]
            else:
                ret1 = []
           
            ret2 = ret
            
            ret = (ret1, ret2)
            
        else:
            ret = ([], [])
            
        return ret
        
    def get_rps(self, current):

        ret = []
        
        wmiobj = win32com.client.GetObject("winmgmts:root/default")
        allrps    = wmiobj.InstancesOf ("SystemRestore")
                
        for rp in allrps:
            ret.append(rp.SequenceNumber)

        if current:
            ret1 = ret[-1]
            ret  = ret[:-1]
        else:
            ret1 = []
            
        ret2 = ret
        
        # return the last one (the one we set) apart from the rest
        return (ret1, ret2)
    
    # gather all the files from the system
    # auto detect OS of image
    def acquire_files(self):       
	
        self.updateLabel("Starting Processing")
    
        self.cursor.execute("insert into evidence_sources (filename) values (?)", [self.compdesc])
        self.evidence_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0] 
    
        if self.acquire_current:
            # this will set a traditional RP on XP type systems and force a VSS creation on vista/7
            self.updateLabel("Setting System Restore Point")
            ret = self.set_system_restore_point()
            if ret == False:
                return ret
            
        (current, backups) = self.get_vss(self.acquire_current)
        
        # vss
        if current != [] or backups != []:
        
            self.updateLabel("Processing the Volume Shadow Server")

            if self.acquire_current:
                self.updateLabel("Acquiring Current Files")
                self.acquire_active_files_vss(current)
                self.conn.commit()    

            if self.acquire_backups:
                self.updateLabel("Acquiring Backup Files")
                self.acquire_backup_files_vss(backups)
			
        # sys restore
        else:
            self.updateLabel("Processing System Restore Point Data")

            (current, backups) = self.get_rps(self.acquire_current)
           
            if self.acquire_current:
                self.updateLabel("Acquiring Current Files")
                self.acquire_active_files(current)
                self.conn.commit()
                
            if self.acquire_backups:
                self.updateLabel("Acquiring Backup Files")
                self.acquire_backup_files(backups)
                
        self.updateLabel("Final Processing")
        self.conn.commit()    
        self.updateLabel("Finished Processing")

        return True



