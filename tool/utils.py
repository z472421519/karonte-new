import os
from random import randint

# Lazy import to avoid requiring binwalk if firmware extraction is not used
try:
    from libraries.extractor.extractor import Extractor
    HAS_EXTRACTOR = True
except ImportError:
    HAS_EXTRACTOR = False
    Extractor = None


MAX_THREADS = 3
N_TYPE_DATA_KEYS = 4
DEFAULT_LOG_PATH = "/tmp/Karonte.txt_" + str(randint(1, 100))
DEFAULT_PICKLE_DIR = "/tmp/pickles"
FW_TMP_DIR = '/tmp/fw/'


def unpack_firmware(fw_path, out_dir):
    """
    Unpacks the firmware
    :param fw_path:  firmware path
    :param out_dir: the directory to extract to
    :return: the path of the unpacked firmware, which is stored in the brand folder
    """
    if not HAS_EXTRACTOR:
        raise ImportError(
            "Firmware extraction requires binwalk. Install it with: pip install binwalk\n"
            "Note: binwalk 2.1.0 from PyPI may not work. You may need to install from source:\n"
            "https://github.com/ReFirmLabs/binwalk"
        )

    input_file = fw_path

    # arguments for the extraction
    rootfs = True
    kernel = False
    enable_parallel = False
    enable_debug = False

    # extract the file to the provided output directory using the FirmAE extractor
    extract = Extractor(input_file, out_dir, rootfs,
                        kernel, enable_parallel, enable_debug)
    extract.extract()

    return out_dir
