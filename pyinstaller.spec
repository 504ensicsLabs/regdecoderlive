# -*- mode: python -*-
projpath = os.path.dirname(os.path.abspath(SPEC))

exeext = ".exe" if 'win' in sys.platform else ""

a = Analysis([os.path.join(HOMEPATH,'support\\_mountzlib.py'), os.path.join(CONFIGDIR,'support\\useUnicode.py'),  os.path.join(projpath, 'guimain.py')], pathex = [HOMEPATH])
              
pyz = PYZ(a.pure, name = os.path.join(BUILDPATH, 'regdecoderlive.pkz'))

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name = os.path.join(projpath, 'dist', 'pyinstaller', 'regdecoderlive' + exeext),
          debug = 0,
          strip = False,
          upx = False,
          icon = "",
          console = 1)

