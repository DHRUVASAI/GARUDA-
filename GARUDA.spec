# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:/Users/dhruv/Downloads/GARUDA--main/GARUDA--main/desktop_launcher.py'],
    pathex=[],
    binaries=[],
    datas=[('C:/Users/dhruv/Downloads/GARUDA--main/GARUDA--main/frontend', 'frontend'), ('C:/Users/dhruv/Downloads/GARUDA--main/GARUDA--main/rules', 'rules')],
    hiddenimports=['uvicorn', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto', 'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.http.auto', 'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan', 'uvicorn.lifespan.on', 'scapy', 'scapy.layers.l2', 'scapy.layers.inet', 'scapy.layers.dhcp', 'sqlalchemy.dialects.sqlite', 'backend.app.main', 'backend.app.routers.admin_and_doctor'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['torch', 'torchvision', 'torchaudio', 'scipy', 'pytest', 'matplotlib', 'IPython', 'PIL'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='GARUDA',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
