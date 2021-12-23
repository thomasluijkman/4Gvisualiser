# −*− coding: UTF−8 −*−
#/**
# * Software Name : CryptoMobile
# * Version : 0.3
# *
# * Copyright 2020. Benoit Michau. P1Sec.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details.
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : CryptoMobile/conv.py
# * Created : 2020-01-21
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/

import hmac
from hashlib import sha256
from struct  import pack
from .utils  import *


__all__ = [
    'KDF',
    'conv_401_A2',
    'conv_401_A3',
    'conv_401_A4',
    'conv_401_A7',
    ]


#------------------------------------------------------------------------------#
# CryptoMobile python toolkit
# conversion functions and Key Derivation Functions
#------------------------------------------------------------------------------#

# 3G / 4G / 5G are using SHA2 for key derivation
def KDF( K, S ):
    """derive S with K according to 3GPP Key Derivation Function defined in TS 33.220"""
    return hmac.new( K, S, sha256 ).digest()

# ------------------------------------------------------------------------------#
# 3G / LTE conversion functions
# ------------------------------------------------------------------------------#
# see TS 33.401, annex A

# Kasme (LTE master key) from CK, IK (3G USIM key)
def conv_401_A2(CK, IK, sn_id, sqn_x_ak):
    """A2 conversion function

    return KASME [32 bytes buffer] from
        3G CK and IK USIM output [16 bytes buffer each],
        SN_ID serving network identity [3 bytes buffer] and
        SQN^AK [6 bytes buffer]
    or None on error
    """
    if len(CK) != 16 or len(IK) != 16 or len(sn_id) != 3 or len(sqn_x_ak) != 6:
        log('ERR', 'conv_A2: invalid args')
        return None
    return KDF(CK + IK, b'\x10' + sn_id + b'\0\x03' + sqn_x_ak + b'\0\x06')


# KeNB (eNB AS master key) from Kasme and uplink NAS count
def conv_401_A3(Kasme, ul_nas_cnt):
    """A3 conversion function

    return KeNB [32 bytes buffer] from
        Kasme [32 bytes buffer] and
        UL NAS count [uint24]
    or None on error
    """
    if len(Kasme) != 32 or not (0 <= ul_nas_cnt < 16777216):
        log('ERR', 'conv_A3: invalid args')
        return None
    return KDF(Kasme, b'\x11' + pack('>IH', ul_nas_cnt, 4))


# NH (for generating KeNB* at HO) from Kasme and SYNC
def conv_401_A4(Kasme, SYNC):
    """A4 conversion function

    return NH [32 bytes buffer] from
        Kasme [32 bytes buffer] and
        SYNC [32 bytes buffer]
    or None on error
    """
    if len(Kasme) != 32 or len(SYNC) != 32:
        log('ERR', 'conv_A4: invalid args')
        return None
    return KDF(Kasme, b'\x12' + SYNC + b'\0\x20')


# NAS / RRC+UP keys derivation from Kasme / KeNB
def conv_401_A7(KEY, alg_dist=0, alg_id=0):
    """A7 conversion function

    return NAS or RRC and UP key [32 bytes buffer] from
        KEY (Kasme or KeNB) [32 bytes buffer],
        algorithm dist [uint8] and
        algorithm id [uint8]
    or None on error
    """
    if len(KEY) != 32 or not (0 <= alg_dist < 256) or not (0 <= alg_id < 256):
        log('ERR', 'conv_A7: invalid args')
        return None
    return KDF(KEY, b'\x15' + pack('>BHBH', alg_dist, 1, alg_id, 1))