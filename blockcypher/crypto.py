from bitcoin import encode, changebase, binascii, bin_to_b58check

import re


def der_strict_encode_sig(v, r, s):
    '''
    Like der_encode_sig but bip66 compliant
    Copied 2015-10-02 from https://github.com/wizardofozzie/pybitcointools/blob/36d4b4a323b78927f6c6487160194aeffd32c61d/bitcoin/transaction.py#L153-L164
    Thanks @wizardofozzie!
    '''
    b1, b2 = encode(r, 256), encode(s, 256)
    if ord(b1[0]) & 0x80:       # add null bytes if leading byte interpreted as negative
        b1 = b'\0' + b1
    if ord(b2[0]) & 0x80:
        b2 = b'\0' + b2
    left = b'\x02' + encode(len(b1), 256, 1) + b1
    right = b'\x02' + encode(len(b2), 256, 1) + b2
    sighex = changebase((b'\x30' + encode(len(left+right), 256, 1) + left + right), 256, 16)
    return sighex


def script_to_address(script, vbyte=0):
    '''
    Like script_to_address but supports altcoins
    Copied 2015-10-02 from https://github.com/mflaxman/pybitcointools/blob/faf56c53148989ea390238c3c4541a6ae1d601f5/bitcoin/transaction.py#L224-L236
    '''
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac' and len(script) == 25:
        return bin_to_b58check(script[3:-2], vbyte)  # pubkey hash addresses
    else:
        if vbyte in [111, 196]:
            # Testnet
            scripthash_byte = 196
        else:
            scripthash_byte = vbyte
        # BIP0016 scripthash addresses
        return bin_to_b58check(script[2:-1], scripthash_byte)
