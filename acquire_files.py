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
import sys, os, sqlite3, wmi, win32com.client, shutil, win32file

from error_classes import *

class acquere_files:

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

        self.db_ops()    
    
    def connect_db(self, directory, db_name):

        dbname = os.path.join(directory, db_name)
        conn = sqlite3.connect(dbname)
        cursor = conn.cursor()

        return (conn, cursor)
      
    def db_ops(self):
 
        (self.conn, self.cursor) = self.connect_db(self.store_dir, "acquire_files.db")
        
        self.cursor.execute("select sql from sqlite_master where type='table' and name=?", ["evidence_sources"])
       
        # need to iniitalize the table of files
        # nothing to do if already created
        if not self.cursor.fetchall():
            
            tables = ["evidence_sources (filename text,   id integer primary key asc)",
                      "partitions       (number int, offset int, evidence_file_id int, id integer primary key asc)"
                      "file_groups      (group_name text, partition_id int, id integer primary key asc)",
                      "reg_type         (type_name text, file_group_id int, id integer primary key asc)",
                      "rp_groups        (rpname text, reg_type_id int, id integer primary key asc)",
                      "registry_files   (filename text,  mtime text, reg_type_id int, file_id int, file_type int, id integer primary key asc)",
                     ]
    
            for table in tables:
                self.cursor.execute("create table " + table)
                
            self.conn.commit()

    # enforces unique group_name and evidence_id pairs
    def group_id(self, group_name):

        part_id = self.part_id

        self.cursor.execute("select id from file_groups where group_name=? and partition_id=?", [group_name, part_id])

        res = self.cursor.fetchone()
        
        # group doesn't exist for evidence file
        if not res:
            self.cursor.execute("insert into file_groups (group_name, partition_id) values (?,?)", [group_name, part_id])
            ret_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]
        
        else:
            ret_id = res[0]

        return ret_id

    def insert_reg_file(self, group_name, tid, file_name, file_type, mtime):

        file_id = self.regfile_ctr

        self.cursor.execute("insert into registry_files (filename, reg_type_id, file_id, file_type, mtime) values (?,?,?,?)", [file_name, tid, file_id, file_type, mtime])

        self.regfile_ctr = self.regfile_ctr + 1
        
    def grab_file(self, type_name, directory, fname, group_id, is_rp=0, realname=""):

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

        if not is_rp:
            tid = self.type_id(type_name, group_id)
        else:
            tid = group_id

        # put info into database
        self.insert_reg_file(type_name, tid, fname, is_rp, mtime)
    
        self.added_files.append(srcfile)

    def type_id(self, type_name, gid=-1):

        if gid == -1:
            group_id = self.gid
        else:
            group_id = gid

        self.cursor.execute("select id from reg_type where type_name=? and file_group_id=?", [type_name, group_id])

        res = self.cursor.fetchone()
        
        # group doesn't exist for evidence file
        if not res:
            self.cursor.execute("insert into reg_type (type_name, file_group_id) values (?,?)", [type_name, group_id])
            ret_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]
        
        else:
            ret_id = res[0]

        return ret_id

    def new_rp(self, rpname, rtype_id):

        self.cursor.execute("insert into rp_groups (rpname, reg_type_id) values (?,?)", [rpname, rtype_id])

        return self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]

    # grabs each registry file from an RP###/snapshot directory
    def parse_rp_folder(self, directory, group_name):
        
        core_id = -1

        # walk the snaphsot dir / it may not exist
        for root, dirs, files in os.walk(directory):
            
            if core_id == -1:
                rp_id     = self.type_id(group_name)
                core_id   = self.new_rp("CORE",   rp_id)
                ntuser_id = self.new_rp("NTUSER", rp_id)                

            for fname in files:
                
                if fname.startswith("_REGISTRY_MACHINE_"):
                    fname = fname[len("_REGISTRY_MACHINE_"):]
                    self.grab_file(group_name, directory, fname, core_id, is_rp=1)
        
                elif fname.startswith("_REGISTRY_USER_"):
                    fname = fname[len("_REGISTRY_USER_"):]
                    self.grab_file(group_name, directory, fname, ntuser_id, is_rp=1)

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
        else:
            print "UPDATE: %s" % msg   
 
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
            (vssfolder, i) = self.get_vss_dir(shadow, i + 1)
            
        return (vssfolder, i)
        
    def get_core_files_vss(self, directory, group_name, is_rp, gid):
    
        corefiles = ["SAM", "SECURITY", "SYSTEM", "SOFTWARE", "DEFAULT"]

        coreelements = [directory, "windows", "system32", "config"]

        corepath = os.path.join(*coreelements)

        for fname in corefiles:
                   
            self.grab_file(group_name, corepath, fname, gid, is_rp=is_rp)
            self.refreshgui()
            
    def get_user_files_vss(self, shadow, group_name, is_rp, gid):
    
        userspath = os.path.join(shadow, "Users")
        
        for username in os.listdir(userspath):
        
            # path to a specific user
            ntpath = os.path.join(userspath, username)
            fpath  = os.path.join(ntpath, "ntuser.dat")
                
            if os.path.exists(fpath):
                self.grab_file(group_name, ntpath, "ntuser.dat", gid, is_rp=is_rp, realname=username)
                self.refreshgui()
                    
    def get_vss_reg_files(self, shadow, linkdir, active, num):
    
        if active:
            group_name = "CORE"
            is_rp = 0
            core_id = self.gid
            ntuser_id = self.gid
        else:
            group_name = "VSS%d" % num
            
            rp_id = self.type_id(group_name, self.gid)

            core_id   = self.new_rp("CORE",   rp_id)
            ntuser_id = self.new_rp("NTUSER", rp_id)        

            is_rp = 1

        self.refreshgui()
        self.get_core_files_vss(linkdir, group_name, is_rp, core_id)
        self.refreshgui()
        
        if active:
            group_name = "NTUSER"
        
        self.refreshgui()      
        self.get_user_files_vss(linkdir, group_name, is_rp, ntuser_id)
        self.refreshgui()
        
    def acquire_active_files_vss(self, shadow, active=1):
    
        # this is where the 'shadow' is mounted
        (linkdir, num) = self.get_vss_dir(shadow)

        self.refreshgui()
        self.get_vss_reg_files(shadow, linkdir, active, num)
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
    
    def set_rp_point(self):

        # this will set a traditional RP on XP type systems and force a VSS creation on vista/7
        self.updateLabel("Setting System Restore Point")
        return self.set_system_restore_point()
     
    # gather all the files from the system
    # auto detect OS of image
    def acquire_files(self):       
	
        self.updateLabel("Starting Processing")
    
        self.cursor.execute("insert into evidence_sources (filename) values (?)", [self.compdesc])
        evi_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0] 
   
        self.cursor.execute("insert into partitions (number, offset, evidence_file_id) values (?, ?, ?)", [0, 0, evi_id])
        self.part_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]
 
        (current, backups) = self.get_vss(self.acquire_current)
        
        # vss
        if current != [] or backups != []:
        
            self.updateLabel("Processing the Volume Shadow Server")

            if self.acquire_backups:

                self.gid = self.group_id("VSS")

                self.updateLabel("Acquiring Backup Files")
                self.acquire_backup_files_vss(backups)
		
            if self.acquire_current:

                if not self.set_rp_point():
                    return False

                self.gid = self.group_id("Current")

                self.updateLabel("Acquiring Current Files")
                self.acquire_active_files_vss(current)
                self.conn.commit()    

        # sys restore
        else:
            self.updateLabel("Processing System Restore Point Data")

            (current, backups) = self.get_rps(self.acquire_current)
         
            if self.acquire_backups:
    
                self.gid = self.group_id("RestorePoints")
                
                self.updateLabel("Acquiring Backup Files")
                self.acquire_backup_files(backups)
           
            if self.acquire_current:

                if not self.set_rp_point():
                    return False

                self.gid = self.group_id("Current")

                self.updateLabel("Acquiring Current Files")
                self.acquire_active_files(current)
                self.conn.commit()
               
        self.updateLabel("Final Processing")
        self.conn.commit()    
        self.updateLabel("Finished Processing. Files successfully acquired.")

        return True



