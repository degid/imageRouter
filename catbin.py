CFE_FS_KERNEL_FILENAME = "RU_DSL-2500U_306043H00_cfe_fs_kernel"
CRC32_INIT_VALUE = 0xffffffff

ADDRESS_LEN = {
    'TAG_LEN': 256,
    'TAGVER_LEN': 4,  # Length of Tag Version
    'SIG1_LEN': 20,  # Company Signature 1 Length
    'SIG2_LEN': 14,  # Company Signature 2 Lenght
    'BOARDID_LEN': 16,  # Length of BoardId
    'ENDIANFLAG_LEN': 2,  # Endian Flag Length
    'CHIPID_LEN': 6,  # Chip Id Length
    'IMAGE_LEN': 10,  # Length of Length Field
    'ADDRESS_LEN': 12,  # Length of Address field
    'DUALFLAG_LEN': 2,  # Dual Image flag Length
    'INACTIVEFLAG_LEN': 2,  # Inactie Flag Length
    'RSASIG_LEN': 20,
    'TOKEN_LEN': 20,
    'DLINK': 32,
    'CRC32_LEN': 4
}

ADDRESS_LEN['RESERVED_LEN'] = (ADDRESS_LEN['TAG_LEN'] - ADDRESS_LEN['TAGVER_LEN'] - ADDRESS_LEN['SIG1_LEN'] - \
                              ADDRESS_LEN['SIG2_LEN'] - ADDRESS_LEN['CHIPID_LEN'] - ADDRESS_LEN['BOARDID_LEN'] - \
                              (4*ADDRESS_LEN['IMAGE_LEN']) - (3*ADDRESS_LEN['ADDRESS_LEN']) - \
                               (3*ADDRESS_LEN['DUALFLAG_LEN']) - (2*ADDRESS_LEN['RSASIG_LEN']))


bcm_tag = [
    ('tagVersion', ADDRESS_LEN['TAGVER_LEN']),              # 0-3: Version of the image tag
    ('sig_1', ADDRESS_LEN['SIG1_LEN']),                     # 4-23: Company Line 1
    ('sig_2', ADDRESS_LEN['SIG2_LEN']),                     # 24-37: Company Line 2
    ('chipid', ADDRESS_LEN['CHIPID_LEN']),                  # 38-43: Chip this image is for
    ('boardid', ADDRESS_LEN['BOARDID_LEN']),                # 44-59: Board name
    ('big_endian', ADDRESS_LEN['ENDIANFLAG_LEN']),          # 60-61: Map endianness -- 1 BE 0 LE
    ('totalLength', ADDRESS_LEN['IMAGE_LEN']),              # 62-71: Total length of image
    ('cfeAddress', ADDRESS_LEN['ADDRESS_LEN']),             # 72-83: Address in memory of CFE
    ('cfeLength', ADDRESS_LEN['IMAGE_LEN']),                # 84-93: Size of CFE
    ('flashImageStart', ADDRESS_LEN['ADDRESS_LEN']),        # 94-105: Address in memory of image start (kernel for OpenWRT, rootfs for stock firmware)
    ('flashRootLength', ADDRESS_LEN['IMAGE_LEN']),          # 106-115: Size of rootfs for flashing
    ('kernelAddress', ADDRESS_LEN['ADDRESS_LEN']),          # 116-127: Address in memory of kernel
    ('kernelLength', ADDRESS_LEN['IMAGE_LEN']),             # 128-137: Size of kernel
    ('dualImage', ADDRESS_LEN['DUALFLAG_LEN']),             # 138-139: Unused at present
    ('inactiveFlag', ADDRESS_LEN['INACTIVEFLAG_LEN']),      # 140-141: Unused at present
    ('reserved', ADDRESS_LEN['RESERVED_LEN']),			    # Reserved for later use
    ('CRCimage', ADDRESS_LEN['CRC32_LEN']),	        # Image validation token (4 unsigned char CRC)
    ('CRCsqsh', ADDRESS_LEN['CRC32_LEN']),	                # Image validation token (4 unsigned char CRC)
    ('CRCkernel', ADDRESS_LEN['CRC32_LEN']),	            # Image validation token (4 unsigned char CRC)
    ('imageValidationTokenRez', ADDRESS_LEN['RSASIG_LEN']-ADDRESS_LEN['CRC32_LEN']*3),	# Image validation token (4 unsigned char CRC)
    #('imageValidationToken', ADDRESS_LEN['RSASIG_LEN']),	# Image validation token (4 unsigned char CRC)
    ('CRCbcmtag', ADDRESS_LEN['CRC32_LEN']),	    # Validation token for tag (from signature_1 to end)
    ('tagValidationToken', ADDRESS_LEN['RSASIG_LEN']-ADDRESS_LEN['CRC32_LEN'])	    # Validation token for tag (from signature_1 to end)
]


def _gen_crc(crc):
    for j in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xEDB88320
        else:
            crc >>= 1
    return crc

_crctable = list(map(_gen_crc, range(256)))

def crc32(ch, crc=0):
    for b in ch:
        crc = (crc >> 8) ^ _crctable[(crc ^ b) & 0xFF]
    return crc


def cut():
    header = {}
    CRC32sum = {}
    with open(CFE_FS_KERNEL_FILENAME, "rb") as file:
        nodecode = ['CRCimage', 'CRCsqsh', 'CRCkernel', 'CRCbcmtag']
        passbin = ['imageValidationTokenRez', 'tagValidationToken', ]

        for n in bcm_tag:
            if nodecode.count(n[0]):
                header[n[0]] = file.read(n[1])
                CRC32sum[n[0]] = 0
                for i, symb in enumerate(header[n[0]], 1):
                    CRC32sum[n[0]] += symb * 256**(4-i)

            elif passbin.count(n[0]):
                file.read(n[1])

            else:
                header[n[0]] = file.read(n[1]).decode('ascii').replace('\x00', '')

        header['cfeLength'] = int(header['cfeLength'])
        header['flashRootLength'] = int(header['flashRootLength'])
        header['kernelLength'] = int(header['kernelLength'])

        for iten in header:
            print('%-20s: %+20s' % (iten, header[iten]))

        file.seek(0, 2)
        print('')
        print('Check...')
        if file.tell() == header['cfeLength'] + header['flashRootLength'] + header['kernelLength'] + ADDRESS_LEN['TAG_LEN'] +  ADDRESS_LEN['DLINK']:
            print('file size: %d [OK]' % file.tell())
        else:
            print('!!! file size: %d, length in data: %d [not match]' % (file.tell(), header['cfeLength'] + header['flashRootLength'] + header['kernelLength'] + ADDRESS_LEN['TAG_LEN'] +  ADDRESS_LEN['DLINK']))


        file.seek(0, 0)
        filecat = [{'name':'bcm.bin', 'len':ADDRESS_LEN['TAG_LEN']},
                   {'name':'cfe.bin', 'len':header['cfeLength']},
                   {'name':'sqsh.bin', 'len':header['flashRootLength']},
                   {'name':'kernel.bin', 'len':header['kernelLength']},
                   {'name':'name.bin', 'len':ADDRESS_LEN['DLINK']}]

        for f in filecat:
            with open(f['name'], "wb") as fileS:
                fileS.write(file.read(f['len']))

        bdata = b''

        # Check bcm.bin
        with open(filecat[0]['name'], "rb") as file:
            bdata = file.read(ADDRESS_LEN['TAG_LEN']-ADDRESS_LEN['TOKEN_LEN'])

        crc = crc32(bdata, CRC32_INIT_VALUE)
        if crc == CRC32sum['CRCbcmtag']:
            print('CRC bcmtag:  0x%08X [OK]' % crc)
        else:
            print('CRC bcmtag:  0x%08X [ERROR]' % crc)

        bdata = b''
        for f in filecat[1:]:
            with open(f['name'], "rb") as file:
                bdata += file.read()

        crc = crc32(bdata, CRC32_INIT_VALUE)
        if crc == CRC32sum['CRCimage']:
            print('CRC image:   0x%08X [OK]' % crc)
        else:
            print('CRC image:   0x%08X [ERROR]' % crc)

        # Check sqsh.bin
        with open(filecat[2]['name'], "rb") as file:
            bdata = file.read()

        crc = crc32(bdata, CRC32_INIT_VALUE)
        if crc == CRC32sum['CRCsqsh']:
            print('CRC sqsh:    0x%08X [OK]' % crc)
        else:
            print('CRC sqsh:    0x%08X [ERROR]' % crc)

        # Check kernel.bin
        with open(filecat[3]['name'], "rb") as file:
            bdata = file.read()

        crc = crc32(bdata, CRC32_INIT_VALUE)
        if crc == CRC32sum['CRCkernel']:
            print('CRC kernel:  0x%08X [OK]' % crc)
        else:
            print('CRC kernel:  0x%08X [ERROR]' % crc)


cut()