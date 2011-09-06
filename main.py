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
import sys, os

import acquire_files

def usage():

    print "%s <case desc> <output directory> <acquire live files (1 or 0)> <acquire backup files <1 or 0>" % sys.argv[0]
    sys.exit(1)

def main():

    if len(sys.argv) != 5:
        usage()
    
    casedesc        = sys.argv[1]
    outputdirectory = sys.argv[2]
    acquire_current = int(sys.argv[3])
    acquire_backups = int(sys.argv[4])
    
    aq = acquire_files.acquire_files(outputdirectory, acquire_current, acquire_backups, casedesc)
    
    aq.acquire_files()
    
    
if __name__ == "__main__":
	main()