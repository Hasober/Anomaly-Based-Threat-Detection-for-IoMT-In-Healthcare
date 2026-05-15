# ids_gui.spec
# ─────────────────────────────────────────────────────────────────────────────
# PyInstaller spec for PatientIDS GUI
# Build with:  pyinstaller ids_gui.spec
# ─────────────────────────────────────────────────────────────────────────────

block_cipher = None

a = Analysis(
    ['ids_gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # sklearn submodules PyInstaller misses
        'sklearn.ensemble._iforest',
        'sklearn.utils._cython_blas',
        'sklearn.neighbors.typedefs',
        'sklearn.neighbors._partition_nodes',
        'sklearn.tree._utils',
        'sklearn.tree._classes',
        # joblib
        'joblib',
        'joblib.externals.loky.backend.managers',
        # numpy / pandas internals
        'numpy.core._methods',
        'numpy.lib.format',
        'pandas._libs.tslibs.base',
        # reportlab
        'reportlab',
        'reportlab.platypus',
        'reportlab.lib.colors',
        'reportlab.lib.pagesizes',
        'reportlab.lib.styles',
        'reportlab.lib.units',
        # paho
        'paho.mqtt.client',
        'paho.mqtt.reasoncodes',
        'paho.mqtt.properties',
        # tkinter (should be auto, but listed for safety)
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib', 'scipy', 'IPython', 'jupyter',
        'PIL._imagingtk',   # exclude large imaging if not used
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PatientIDS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,           # compress with UPX if available (smaller EXE)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,      # no black terminal window — GUI only
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='ids_icon.ico',  # uncomment and provide a .ico file for a custom icon
)
