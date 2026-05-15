# ids_gui.spec
# ─────────────────────────────────────────────────────────────────────────────
# PyInstaller spec for PatientIDS GUI
# Build with:  python -m PyInstaller ids_gui.spec
# ─────────────────────────────────────────────────────────────────────────────

block_cipher = None

a = Analysis(
    ['ids_gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # ── scipy (required by scikit-learn internally) ───────────────────────
        'scipy',
        'scipy._lib',
        'scipy._lib.messagestream',
        'scipy.sparse',
        'scipy.sparse.csgraph',
        'scipy.sparse.csgraph._validation',
        'scipy.sparse._compressed',
        'scipy.sparse._csr',
        'scipy.sparse._csc',
        'scipy.sparse._coo',
        'scipy.sparse.linalg',
        'scipy.special',
        'scipy.special._ufuncs',
        'scipy.special._cython_special',
        'scipy.stats',
        'scipy.optimize',

        # ── scikit-learn ──────────────────────────────────────────────────────
        'sklearn',
        'sklearn.ensemble',
        'sklearn.ensemble._iforest',
        'sklearn.ensemble._base',
        'sklearn.ensemble._forest',
        'sklearn.utils',
        'sklearn.utils._cython_blas',
        'sklearn.utils.validation',
        'sklearn.utils._weight_vector',
        'sklearn.utils._bunch',
        'sklearn.utils.murmurhash',
        'sklearn.neighbors',
        'sklearn.neighbors.typedefs',
        'sklearn.neighbors._partition_nodes',
        'sklearn.tree',
        'sklearn.tree._utils',
        'sklearn.tree._classes',
        'sklearn.tree._criterion',
        'sklearn.tree._splitter',
        'sklearn.preprocessing',
        'sklearn.preprocessing._encoders',
        'sklearn.preprocessing._data',
        'sklearn.pipeline',
        'sklearn.base',
        'sklearn.metrics',
        'sklearn.linear_model',

        # ── joblib ────────────────────────────────────────────────────────────
        'joblib',
        'joblib.externals',
        'joblib.externals.loky',
        'joblib.externals.loky.backend',
        'joblib.externals.loky.backend.managers',
        'joblib.externals.cloudpickle',

        # ── numpy ─────────────────────────────────────────────────────────────
        'numpy',
        'numpy.core',
        'numpy.core._methods',
        'numpy.core._multiarray_umath',
        'numpy.lib',
        'numpy.lib.format',
        'numpy.random',
        'numpy.linalg',
        'numpy.fft',

        # ── pandas ────────────────────────────────────────────────────────────
        'pandas',
        'pandas._libs',
        'pandas._libs.tslibs',
        'pandas._libs.tslibs.base',
        'pandas._libs.tslibs.np_datetime',
        'pandas._libs.tslibs.timedeltas',
        'pandas._libs.tslibs.timestamps',
        'pandas._libs.tslibs.nattype',
        'pandas._libs.tslibs.offsets',
        'pandas._libs.tslibs.period',
        'pandas._libs.tslibs.parsing',
        'pandas._libs.hashtable',
        'pandas._libs.index',
        'pandas._libs.lib',
        'pandas._libs.missing',
        'pandas._libs.reduction',
        'pandas._libs.ops',

        # ── reportlab ─────────────────────────────────────────────────────────
        'reportlab',
        'reportlab.platypus',
        'reportlab.platypus.doctemplate',
        'reportlab.platypus.tables',
        'reportlab.platypus.paragraph',
        'reportlab.platypus.flowables',
        'reportlab.lib',
        'reportlab.lib.colors',
        'reportlab.lib.pagesizes',
        'reportlab.lib.styles',
        'reportlab.lib.units',
        'reportlab.lib.enums',
        'reportlab.lib.fonts',
        'reportlab.pdfgen',
        'reportlab.pdfgen.canvas',
        'reportlab.pdfbase',
        'reportlab.pdfbase.ttfonts',
        'reportlab.pdfbase.pdfmetrics',
        'reportlab.graphics',

        # ── paho MQTT ─────────────────────────────────────────────────────────
        'paho',
        'paho.mqtt',
        'paho.mqtt.client',
        'paho.mqtt.reasoncodes',
        'paho.mqtt.properties',
        'paho.mqtt.packettypes',
        'paho.mqtt.subscribe',
        'paho.mqtt.publish',

        # ── psutil ────────────────────────────────────────────────────────────
        'psutil',
        'psutil._pswindows',
        'psutil._psutil_windows',

        # ── tkinter ───────────────────────────────────────────────────────────
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.font',
        'tkinter.scrolledtext',

        # ── stdlib extras ─────────────────────────────────────────────────────
        'queue',
        'threading',
        'xml.etree.ElementTree',
        'csv',
        'socket',
        'collections',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Only exclude things truly not needed — do NOT exclude scipy
        'matplotlib',
        'IPython',
        'jupyter',
        'notebook',
        'pytest',
        'PIL._imagingtk',
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
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,      # no console window — GUI only
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='ids_icon.ico',
)
