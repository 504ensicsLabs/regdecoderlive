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
import sys, os, sqlite3, win32com.client, shutil, win32file, platform, pytsk3, ctypes

from error_classes import *

# based on pytsk3 documentation
# returns the file as a python string
def read_file(fd):

    data = ""
    offset = 0
    BUFF_SIZE = 1024 * 1024

    if fd.info.meta:
        size = fd.info.meta.size
    else:
        return ""            

    while offset < size:
        available_to_read = min(BUFF_SIZE, size - offset)
        cur = fd.read_random(offset, available_to_read)
    
        if not cur:
            break

        data = data + cur
        offset += len(cur)

    return data

# grabs file from the raw drive
def grab_raw_file(self, f, type_name, fname, group_id, is_rp=0, realname=""):

    data = read_file(f)
     
    if data == "":
        print "grab_file: unable to acquire file %s from %s" % (fname, type_name)
        return

    # copy file to acquire_store
    fd = open(os.path.join(self.aq.store_dir, "%d" % self.aq.regfile_ctr), "wb")
    fd.write(data)
    fd.close()

    if f.info.meta:
        mtime = f.info.meta.mtime
    else:
        mtime = 0

    if realname:
        fname = realname

    # notes about this
    # is_rp controls whether its a file from a sys RP
    # group_id for non-rp is core/ntuser in the first level
    # group_id is last level for rp files

    # put info into database
    if not is_rp:
        tid = self.aq.type_id(type_name, group_id)
    else:
        tid = group_id

    self.aq.insert_reg_file(type_name, tid, fname, is_rp, mtime)
    
    self.aq.added_files = self.aq.added_files + 1
    
class rp_ops:

    def __init__(self, osobj):
        self.os = osobj
        self.aq = osobj.aq

    # grabs each registry file from an RP###/snapshot directory
    def _parse_rp_folder(self, fs, directory, rpname, group_id):

        if directory.info.meta:
            # open file as a directory
            directory = fs.open_dir(inode=directory.info.meta.addr)
        else:
            print "parse_rp_folder: unable to get %s" % rpname
            return 

        # puts the "RP###" folder under the _restore directory
        rp_id = self.aq.type_id(rpname, group_id)

        core_id   = self.aq.new_rp("CORE",   rp_id)
        ntuser_id = self.aq.new_rp("NTUSER", rp_id)

        # walk the snaphsot dir
        for f in directory:
            
            fname = f.info.name.name

            if fname.startswith("_REGISTRY_MACHINE_"):
                fname = fname[len("_REGISTRY_MACHINE_"):]
                grab_raw_file(self, f, rpname, fname, core_id, is_rp=1)
    
            elif fname.startswith("_REGISTRY_USER_"):
                fname = fname[len("_REGISTRY_USER_"):]
                grab_raw_file(self, f, rpname, fname, ntuser_id, is_rp=1)
    
    # parse RP structure
    def _parse_system_restore(self, fs, directory, group_id):

        if directory.info.meta:
            # directory is sent in as a pytsk3.File
            directory = fs.open_dir(inode=directory.info.meta.addr)
        else:
            print "parse_system_restore: unable to do anything"
            return

        # this uglyness walks each RP###/snapshot dir and sends to the file grab function
        for subdir in directory:
        
            fname = subdir.info.name.name

            if fname.startswith("RP"):

                # only process still allocated restore points
                if subdir.info.meta and (int(subdir.info.meta.flags) & 1) == 1: 
                    subdir = fs.open_dir(inode=subdir.info.meta.addr)

                    for f in subdir:

                        name = f.info.name.name

                        if name == "snapshot":
               
                            # grab the registry files
                            self._parse_rp_folder(fs, f, fname, group_id)

        
    def _handle_sys_restore(self, fs):

        try:
            directory = fs.open_dir("System Volume Information")
        except Exception, e:
            print "Bug: sys vol info: %s" % str(e)
            return

        # this will hit restore files for XP
        for f in directory:
            
            fname = f.info.name.name

            if fname.startswith("_restore{"):
                self.aq.group_id(fname)
                self._parse_system_restore(fs, f, self.aq.gid)
    
    def _acquire_rps(self, fs):
    
        self._handle_sys_restore(fs)
        
    def acquire_files(self, fs):
                    
        self.aq.updateLabel("Acquiring Backup Files")        
    
        self._acquire_rps(fs)

'''
This only handles grabbing registry files from volume shadow service backups
'''
class vss_ops:

    def __init__(self, osobj):
        self.os = osobj
        self.aq = osobj.aq

        
    def _grab_file(self, type_name, directory, fname, group_id, is_rp=0, realname=""):

        srcfile  = os.path.join(directory, fname)
        destfile = os.path.join(self.aq.store_dir, "%d" % self.aq.regfile_ctr)
        
        try:
            mtime = os.path.getmtime(srcfile)
        except:
            print "directory broke: %s" % directory
            print os.listdir(directory)

        shutil.copy(srcfile, destfile)
        
        if realname:
            fname = realname

        if not is_rp:
            tid = self.aq.type_id(type_name, group_id)
        else:
            tid = group_id

        # put info into database
        self.aq.insert_reg_file(type_name, tid, fname, is_rp, mtime)
    
        self.aq.added_files = self.aq.added_files + 1
        
    def _get_shadows(self):
        
        # kind of bruteforces possible shadow copy paths
        
        ret = []
        
        for i in xrange(0, 4096):
        
            path = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" + "%d" % i

            try:
                fd = open(path, "rb")
                ret.append(path)
            except:
                pass
                
        return ret
    
    def _get_core_files_vss(self, directory, group_name, is_rp, gid):
    
        corefiles = ["SAM", "SECURITY", "SYSTEM", "SOFTWARE", "DEFAULT"]

        coreelements = [directory, "windows", "system32", "config"]

        corepath = os.path.join(*coreelements)

        for fname in corefiles:
                   
            self._grab_file(group_name, corepath, fname, gid, is_rp=is_rp)
            self.aq.refreshgui()
            
    def _get_user_files_vss(self, shadow, group_name, is_rp, gid):
    
        userspath = os.path.join(shadow, "Users")
        
        for username in os.listdir(userspath):
        
            # path to a specific user
            ntpath = os.path.join(userspath, username)
            fpath  = os.path.join(ntpath, "ntuser.dat")
                
            if os.path.exists(fpath):
                self._grab_file(group_name, ntpath, "ntuser.dat", gid, is_rp=is_rp, realname=username)
                self.aq.refreshgui()
    
    def _get_vss_reg_files(self, linkdir, active):

        group_name = "VSS%d" % self.aq.vss_ctr
        
        rp_id     = self.aq.type_id(group_name, self.aq.gid)
        core_id   = self.aq.new_rp("CORE",   rp_id)
        ntuser_id = self.aq.new_rp("NTUSER", rp_id)        
        
        is_rp = 1

        self.aq.vss_ctr = self.aq.vss_ctr + 1
        
        self.aq.refreshgui()
        
        self._get_core_files_vss(linkdir, group_name, is_rp, core_id)
            
        self.aq.refreshgui()
        
        self._get_user_files_vss(linkdir, group_name, is_rp, ntuser_id)
            
        self.aq.refreshgui()
  
    # this gets the directory to make the symbolic link in
    def _get_vss_dir(self, shadow, i=0):
    
        vssfolder  = os.getenv("SystemDrive") + "\\" + "registrydecodervss%d" % i

        try:
            win32file.CreateSymbolicLink(vssfolder, shadow, 1)
        except Exception, e:
            #print "Exception: %s" % str(e)
            (vssfolder, i) = self._get_vss_dir(shadow, i + 1)
            
        return (vssfolder, i)
       
    def _acquire_backup_files(self, shadows):
            
        for shadow in shadows:
            
            (linkdir, unused) = self._get_vss_dir(shadow)

            self.aq.refreshgui()
            self._get_vss_reg_files(linkdir, 0)
            self.aq.refreshgui()
            
            win32file.RemoveDirectory(linkdir)
 
    def acquire_files(self, ignore):
    
        backups = self._get_shadows()

        self.aq.group_id("VSS")

        self.aq.updateLabel("Acquiring Backup Files")
        self._acquire_backup_files(backups)

# pulls files from under the filesystem to avoid permissions or open locks
class raw_ops:

    def __init__(self, osobj):
        self.os = osobj
        self.aq = osobj.aq
        
    '''
    this ugly function is b/c windows has a case-insentive FS,
    tsk doesn't so we have to try to read the file as both lower and upper case
    if neither of those appear then we have to bail
    '''
    def open_hive(self, fs, directory, fname, raiseex=1):
            
        fpath = directory + "/" + fname.lower()
        
        try:
            f = fs.open(path=fpath)
        except:

            try:
                fpath = directory + "/" + fname.upper()
                f = fs.open(path=fpath)
            except:
                if raiseex:
                    print "BUG: could not find a valid name for %s" % fpath
                    #raise RDError("BUG: could not find a valid name for %s" % fpath)
                
                f = None

        return f    
        
    def get_core_files(self, fs, group_id):

        dpath = "/".join(self.os.core_dir)

        core_dir = fs.open_dir(path=dpath)

        for fname in self.os.core_hives:
        
            f = self.open_hive(fs, dpath, fname)   

            grab_raw_file(self, f, "CORE", fname, group_id)
        
    def get_user_files(self, fs, group_id):
        
        fd = fs.open_dir(path=self.os.user_dir)
            
        if hasattr(fd, "info"):
            dname = fd.info.fs_file.name.name
        elif hasattr(fd, "fs_file"):
            dname = fd.fs_file.info.name.name
        else:
            raise RDError("Unable to get dname")

        # each user directory
        for f in fd:
            
            fname = f.info.name.name

            if fname not in [".", ".."]:

                flist = [dname, fname]
                    
                ff = self.open_hive(fs, "/".join(flist), "NTUSER.dat", 0)
   
                if ff: 
                    # open the user's directory
                    rname = ff.info.name.name

                    grab_raw_file(self, ff, "NTUSER", "NTUSER.dat", group_id, realname=fname)    
        
    def acquire_files(self, fs):
    
        self.aq.group_id("Current")

        self.aq.updateLabel("Acquiring Current Files")
        
        core_id    = self.aq.gid
        ntuser_id  = self.aq.gid
    
        self.get_core_files(fs, core_id)
        self.get_user_files(fs, ntuser_id)
        
        
'''
info per-os on how to acquire current and backup hives
'''     
class XP:

    def __init__(self, aq):
    
        self.aq = aq
    
        self.core_dir   = ["WINDOWS", "system32", "config"]
        self.core_hives = ["default", "SAM" , "SECURITY", "software", "system"]
        
        self.user_dir   = "Documents and Settings"
        self.user_file  = "NTUSER.DAT"
                    
        self.current_ops = raw_ops(self)
        self.backup_ops  = rp_ops(self)

    
class vista7:

    def __init__(self, aq):
    
        self.aq = aq
    
        self.core_dir   = ["Windows", "System32", "config"]
        self.core_hives = ["SYSTEM", "SOFTWARE", "SECURITY", "SAM", "DEFAULT"]
        
        self.user_dir   = "Users"
        self.user_file  = "NTUSER.DAT"
        
        self.current_ops = raw_ops(self)
        self.backup_ops  = vss_ops(self)   
        
class acquire_files:

    def __init__(self, output_directory, acquire_current, acquire_backups, compdesc, gui=None):
    
        self.added_files = 0

        self.output_directory = output_directory
        self.acquire_current  = acquire_current
        self.acquire_backups  = acquire_backups
        self.gui = gui
        self.compdesc = compdesc
        
        self.regfile_ctr = 0
        self.img_ctr     = 0
        self.vss_ctr     = 0
        
        self.store_dir = os.path.join(output_directory, "registryfiles")

        self.check_admin()

        # this makes testing easier to avoid exception        
        try:
            os.mkdir(self.store_dir)
        except Exception, e:
            pass

        self.db_ops()

    def check_admin(self):
        if (ctypes.windll.shell32.IsUserAnAdmin() == 0):
            self.fatal("This program must be run as an Administrator!")          
    
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
                      "partitions       (number int, offset int, evidence_file_id int, id integer primary key asc)",
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
            
        self.gid = ret_id

    def insert_reg_file(self, group_name, tid, file_name, file_type, mtime):

        file_id = self.regfile_ctr

        self.cursor.execute("insert into registry_files (filename, reg_type_id, file_id, file_type, mtime) values (?,?,?,?,?)", [file_name, tid, file_id, file_type, mtime])

        self.regfile_ctr = self.regfile_ctr + 1

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

        
    def updateLabel(self, msg):
    
        if self.gui:
            self.gui.resultsLabel.setText(msg)
            self.refreshgui()
        else:
            print "UPDATE: %s" % msg  

    def fatal(self, msg):
        self.message(msg)
        sys.exit()

    def message(self, msg): 
        if self.gui:
            self.gui.msgBox(msg)
        else:
            print msg
 
    def refreshgui(self):

        if self.gui:
            self.gui.update()
            self.gui.app.processEvents()
            self.gui.update()
            self.gui.app.processEvents()
        
                            
     
    # gather all the files from the system
    # auto detect OS of image
    def acquire_files(self):       
	
        self.updateLabel("Starting Processing")
    
        self.cursor.execute("insert into evidence_sources (filename) values (?)", [self.compdesc])
        evi_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0] 
   
        self.cursor.execute("insert into partitions (number, offset, evidence_file_id) values (?, ?, ?)", [0, 0, evi_id])
        self.part_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]
 
        # find the OS install drive and its raw/partition path
        letter  = os.getenv("SystemDrive")
        if letter[-1] != "\\":
            letter = letter + "\\"

        # raw path to the system drive
        path = win32file.GetVolumeNameForVolumeMountPoint(letter)
        path = path.replace("?",".")
        path = path.rstrip("\\")
                
        img_info  = pytsk3.Img_Info(path)
        fs        = pytsk3.FS_Info(img_info)
        
        winver = platform.release()

        # vss
        if winver in ['Vista', '7']:
        
            self.updateLabel("Processing Vista/7")
            
            cls = vista7(self)

        # sys restore
        elif winver == 'XP':

            self.updateLabel("Processing Windows XP")

            cls = XP(self)

        else:               
            self.message("Your operating system is unsupported. Please file a bug if you are running on Windows 7, Vista, or XP.") 
            return False

        if self.acquire_backups:
            cls.backup_ops.acquire_files(fs)     
            self.conn.commit()
           
        if self.acquire_current:
            cls.current_ops.acquire_files(fs)
            self.conn.commit()
            
        self.updateLabel("Final Processing")
        self.conn.commit()    
        self.updateLabel("Finished Processing. Files successfully acquired.")

        return True



