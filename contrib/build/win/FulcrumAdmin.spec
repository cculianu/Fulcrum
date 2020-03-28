# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['FulcrumAdmin'],
             pathex=['Z:\\tmp\\tmp'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
# We need to delete any .DLL's coming in from windows\system32 since they are
# bad fake WINE DLL's and this breaks on real Windows.
bins = []
for b in a.binaries:
    if 'windows\\system32\\' not in b[1].lower():
        bins.append(b)
a.binaries = bins
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='FulcrumAdmin',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True )
