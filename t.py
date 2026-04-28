from dataclasses import dataclass
from typing import Callable
import base64

@dataclass
class TransformConfig:
    skip:   int
    ops:    dict[int, Callable[[int], int]]

#                           rc_key   transform key
type DataTransform =  tuple[bytes,   bytes,        TransformConfig]

#                           rc_key   transform key 1  transform key 2
type ParamTransform = tuple[bytes,   bytes,           bytes,           TransformConfig]

def ADD(n):
    return lambda k: k + n

def SUB(n):
    return lambda k: k - n

def ROL(n):
    return lambda k: ((k << n) | (k >> 8-n)) & 0xFF

def ROR(n):
    return lambda k: ((k >> n) | (k << 8-n)) & 0xFF

def XOR(n):
    return lambda k: k ^ n

b64d = lambda data: base64.urlsafe_b64decode(data)

PARAMS_ROUNDS: list[ParamTransform] = [
        (
            b'\xd7v\x03\xbb\xae\xee\x0e\x01\\\xce\x8d\xc3\x9e\xe4\xc8Q\x1a\x9a\xb3\x89_0C\xc0\r\x8e\x89i\xea\xa4\xcb\xec',
             
            b'\xc8L\xbb\xc0\x17\xc1s\xe8,`\xf8\x90/\xfe\x03}\xdd) \x16E\xcc\xcc+\xb6TP\x1b\x03\x17\xcbt',
            b'\xca\xb3\xfe\x11P5\x0f',

            TransformConfig(
                7,
                {
                    0: lambda k: k + 115,
                    1: lambda k: k - 12,
                    2: lambda k: ((k >> 1) | (k << 7)) & 0xFF,
                    3: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    4: lambda k: k - 42,
                    5: lambda k: k + 143,
                    6: lambda k: k - 42,
                    7: lambda k: k - 241,
                    8: lambda k: ((k >> 1) | (k << 7)) & 0xFF,
                    9: lambda k: k + 115,
                }
            ), 
        ),
        (
            b'\xbd\x9d\xb7E>\xe9m)q\xc2,\xa0\x90wuv\x14\xe8"K\xbcH\xd1\xcf\x0b\xa5w\xe8\xbe\x1c\x9f\x03',

            b'A},-\xa8N\x07%\x8bqa\xa7\xbf\xa9}\xf2\xf4.uj\x9dD\x8d\xc39p]\x8a\xdf[\xc4!',
            b'X\x9c \xa8)\x9f',

            TransformConfig(
                6,
                {
                    0: lambda k: k + 115,
                    1: lambda k: k - 12,
                    2: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    3: lambda k: k - 42,
                    4: lambda k: k + 143,
                    5: lambda k: k - 241,
                    6: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    7: lambda k: k - 20,
                    8: lambda k: k + 115,
                    9: lambda k: k + 143,
                }
            ), 
        ),
        (
            b'\x06E\x88\xf1\xf7\xaaJP\xd9(\xca\xbak\x07\xf3ZU2\xa6_<\x9f>\xb9)Tf\xa4}\x11X\x87',

            b'\xbf\xb1\x08\xa6$\x10\x8d\xdd\x81\x1a\xe2s1\xb0@\xd2\xa3\xd6\r$\xbe\xc12QC\xbb\x86\xcd\x9e\xab$\xab',
            b'\xd5%\x11y\x89BD',

            TransformConfig(
                7,
                {
                    0: lambda k: k + 115,
                    1: lambda k: k - 188,
                    2: lambda k: k + 143,
                    3: lambda k: ((k << 2) | (k >> 6)) & 0xFF,
                    4: lambda k: ((k >> 1) | (k << 7)) & 0xFF,
                    5: lambda k: k ^ 177,
                    6: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    7: lambda k: k - 241,
                    8: lambda k: k + 143,
                    9: lambda k: k - 12,
                }
            ), 
        ),
        (
            b'F\x8b\xa0\x8e!G\x91"\xac\xdb@\xd9\xe8\x15\x97\x89l\x10PfW\xb6\xc7\x99#$\x16+>^\x1b~',

            b',\xbf{s\n\x03\xa0n\\\xc3\xc4&\x84\x8f\x8aIl\xdf[\xef\x15z\x12!\xfa)\xd3\xc6uI\xda\x9b',
            b'\xe7h\x83\xaa<\xe5\xa9\xef',

            TransformConfig(
                8,
                {
                    0: lambda k: k - 12,
                    1: lambda k: k ^ 177,
                    2: lambda k: ((k >> 1) | (k << 7)) & 0xFF,
                    3: lambda k: k + 143,
                    4: lambda k: k - 20,
                    5: lambda k: k + 143,
                    6: lambda k: k - 20,
                    7: lambda k: ((k >> 1) | (k << 7)) & 0xFF,
                    8: lambda k: ((k >> 1) | (k << 7)) & 0xFF,
                    9: lambda k: k ^ 177,
                }
            ), 
        ),
        (
            b'S\xd2\xd1`R\xf6\xcdu8N\xd0\x0b!\x80\xe3\xfaP\x80M\x19?\x10\x9bG\xef\xfc\xbb\xa9\x86\r\x96\x1f',

            b'{\xf1\xad}\xf1CN\xf9\xf0\xec\xb0Q\x8b\x10\x03\xfa!\xa2\xc6:\x93\xab\xd9\x08gY\xb4\x1e?\xac\xe9\xf6',
            b'\xc5\xbd\x97\xc0sA',

            TransformConfig(
                6,
                {
                    0: lambda k: k - 20,
                    1: lambda k: k + 143,
                    2: lambda k: k + 115,
                    3: lambda k: k ^ 177,
                    4: lambda k: k - 12,
                    5: lambda k: k ^ 177,
                    6: lambda k: k - 188,
                    7: lambda k: k + 143,
                    8: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    9: lambda k: ((k << 2) | (k >> 6)) & 0xFF,
                }
            ), 
        ),

]


IFRAME_ROUNDS: list[DataTransform] = [
    (
        b'S\xd2\xd1`R\xf6\xcdu8N\xd0\x0b!\x80\xe3\xfaP\x80M\x19?\x10\x9bG\xef\xfc\xbb\xa9\x86\r\x96\x1f',
        b'{\xf1\xad}\xf1CN\xf9\xf0\xec\xb0Q\x8b\x10\x03\xfa!\xa2\xc6:\x93\xab\xd9\x08gY\xb4\x1e?\xac\xe9\xf6',
        TransformConfig(
            6,
            {
                0: lambda k: k + 20,
                1: lambda k: k - 143,
                2: lambda k: k - 115,
                3: lambda k: k ^ 177,
                4: lambda k: k + 12,
                5: lambda k: k ^ 177,
                6: lambda k: k + 188,
                7: lambda k: k - 143,
                8: lambda k: ((k >> 4) | (k << 4)) & 0xFF,
                9: lambda k: ((k >> 2) | (k << 6)) & 0xFF,
            }
        ),
    ),
    (
        b'F\x8b\xa0\x8e!G\x91"\xac\xdb@\xd9\xe8\x15\x97\x89l\x10PfW\xb6\xc7\x99#$\x16+>^\x1b~',
        b',\xbf{s\n\x03\xa0n\\\xc3\xc4&\x84\x8f\x8aIl\xdf[\xef\x15z\x12!\xfa)\xd3\xc6uI\xda\x9b',
        TransformConfig(
            8,
            {
                0: lambda k: k + 12,
                1: lambda k: k ^ 177,
                2: lambda k: ((k << 1) | (k >> 7)) & 0xFF,
                3: lambda k: k - 143,
                4: lambda k: k + 20,
                5: lambda k: k - 143,
                6: lambda k: k + 20,
                7: lambda k: ((k << 1) | (k >> 7)) & 0xFF,
                8: lambda k: ((k << 1) | (k >> 7)) & 0xFF,
                9: lambda k: k ^ 177,
            }
        ),
    ),
    (
        b'\x06E\x88\xf1\xf7\xaaJP\xd9(\xca\xbak\x07\xf3ZU2\xa6_<\x9f>\xb9)Tf\xa4}\x11X\x87',
        b'\xbf\xb1\x08\xa6$\x10\x8d\xdd\x81\x1a\xe2s1\xb0@\xd2\xa3\xd6\r$\xbe\xc12QC\xbb\x86\xcd\x9e\xab$\xab',
        TransformConfig(
            7,
            {
                0: lambda k: k - 115,
                1: lambda k: k + 188,
                2: lambda k: k - 143,
                3: lambda k: ((k >> 2) | (k << 6)) & 0xFF,
                4: lambda k: ((k << 1) | (k >> 7)) & 0xFF,
                5: lambda k: k ^ 177,
                6: lambda k: ((k >> 4) | (k << 4)) & 0xFF,
                7: lambda k: k + 241,
                8: lambda k: k - 143,
                9: lambda k: k + 12,
            }
        ),
    ),
    (
        b'\xbd\x9d\xb7E>\xe9m)q\xc2,\xa0\x90wuv\x14\xe8"K\xbcH\xd1\xcf\x0b\xa5w\xe8\xbe\x1c\x9f\x03',
        b'A},-\xa8N\x07%\x8bqa\xa7\xbf\xa9}\xf2\xf4.uj\x9dD\x8d\xc39p]\x8a\xdf[\xc4!',
        TransformConfig(
            6,
            {
                0: lambda k: k - 115,
                1: lambda k: k + 12,
                2: lambda k: ((k >> 4) | (k << 4)) & 0xFF,
                3: lambda k: k + 42,
                4: lambda k: k - 143,
                5: lambda k: k + 241,
                6: lambda k: ((k >> 4) | (k << 4)) & 0xFF,
                7: lambda k: k + 20,
                8: lambda k: k - 115,
                9: lambda k: k - 143,
            }
        ),
    ),
    (
        b'\xd7v\x03\xbb\xae\xee\x0e\x01\\\xce\x8d\xc3\x9e\xe4\xc8Q\x1a\x9a\xb3\x89_0C\xc0\r\x8e\x89i\xea\xa4\xcb\xec',
        b'\xc8L\xbb\xc0\x17\xc1s\xe8,`\xf8\x90/\xfe\x03}\xdd) \x16E\xcc\xcc+\xb6TP\x1b\x03\x17\xcbt',
        TransformConfig(
            7,
            {
                0: lambda k: k - 115,
                1: lambda k: k + 12,
                2: lambda k: ((k << 1) | (k >> 7)) & 0xFF,
                3: lambda k: ((k >> 4) | (k << 4)) & 0xFF,
                4: lambda k: k + 42,
                5: lambda k: k - 143,
                6: lambda k: k + 42,
                7: lambda k: k + 241,
                8: lambda k: ((k << 1) | (k >> 7)) & 0xFF,
                9: lambda k: k - 115,
            }
        ),
    ),
]


SOURCES_ROUNDS: list[DataTransform] = [
        (
            b"\x8c\x9bI\x89^X\x83\x12\x9ah]\xf7\xf8@'b_8\x15\xa3'\x00A\xf5\xf9\xfc\xd5b\xcd\xc3\x18\x9c",
            b'\xa3\x85\xd7*\x1bN[\x8f\x8dn\\;TEgVo\x08\xcc\x0cl\xe8\xffd\x85\x9a+\x14\xac\x98\x8f\xa6',
            TransformConfig(
                7, 
                {
                    0: lambda k: k + 52,
                    1: lambda k: ((k << 1) | (k >> 7)) & 0xFF,
                    2: lambda k: k - 23,
                    3: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    4: lambda k: ((k >> 4) | (k << 4)) & 0xFF,
                    5: lambda k: k + 96,
                    6: lambda k: k + 149,
                    7: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    8: lambda k: ((k >> 4) | (k << 4)) & 0xFF,
                    9: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                }
            ),
        ),
        (
            b'\x0bU\xa3\xfc\x01\x9e\xde\xe6H0\xc8\xf2\xb8m\x92\xe50\xbb\xb4\x18\xb5\xe3$U\xda\xee\xb2\xad\xb0\x8e\x0e\x11',
            b"\xcbfd0\xd9\x16\xe0'3\x11\x87\xe8\x87\xbbxI2\xfb\x97+p\xa4\n_}q\x0e\xb9\xff^\xa0\x80",
            TransformConfig(
                5, 
                {
                    0: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    1: lambda k: k + 52,
                    2: lambda k: k - 23,
                    3: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    4: lambda k: ((k >> 5) | (k << 3)) & 0xFF,
                    5: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    6: lambda k: k + 149,
                    7: lambda k: k + 96,
                    8: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    9: lambda k: ((k >> 5) | (k << 3)) & 0xFF,

                }
            ),
        ),
        (
            b'\xf5\x16\x03\xbd\r\xd2\xf8%\xa2\xbf(>\xe9g\xddmQ`\xf6\xee\x94>\x90kt:\xa6\xb8\xf5\rm$',
            b'"\x9f9\xf2\xda;\xa7\x94e\xff\x95\x81Y8\xc5\x1c\xe6\xc7\xfa\xf0\xf9\x0cn;\xc0\xc0\x8eyS\x81[\x92',
            TransformConfig(
                8, 
                {
                    0: lambda k: ((k >> 5) | (k << 3)) & 0xFF,
                    1: lambda k: k + 96,
                    2: lambda k: ((k << 1) | (k >> 7)) & 0xFF,
                    3: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    4: lambda k: ((k >> 4) | (k << 4)) & 0xFF,
                    5: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    6: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    7: lambda k: k + 52,
                    8: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    9: lambda k: k + 96,
                }
            ),
        ),
        (
            b"\x0fal\x04\x87qe\xa2'\x96l9\xca\xb0i\r\xed\xad\x80\x087\x03\xde\x1b\xcd2i\x9eW\x89j`",
            b'\xa0\xbbp\t\x15\x8f\x8c4\xe8\x0e\x1a-\xd6\xd0N|Y\xa0U\xd4U\x9b\xe6\xef\xa4\xb8\xdd\xb8>\xd1\xbf&',
            TransformConfig(
                7, 
                {
                    0: lambda k: ((k << 1) | (k >> 7)) & 0xFF,
                    1: lambda k: k + 238,
                    2: lambda k: ((k >> 5) | (k << 3)) & 0xFF,
                    3: lambda k: k + 149,
                    4: lambda k: k + 238,
                    5: lambda k: k + 52,
                    6: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    7: lambda k: ((k >> 5) | (k << 3)) & 0xFF,
                    8: lambda k: ((k >> 4) | (k << 4)) & 0xFF,
                    9: lambda k: k + 149,
                }
            ),
        ),
        (
            b'{\x88\xf6\x1d\xcb^\xb7\xdd\x9ac\x15\x9c\x1b\xffW\x86\xcf\x91\xee\xaa\xac\xff\xfe\xb2t]\xa9\xea\x90\xcdE\xac',
            b'\xed-\xad\xab\xbc\n\x84>>\\\x1d$7\xe82\xde\x1e\xa6\x9c4\xb9\x8c\xb4!,5k\xab@\xd4\xb1\xe3',
            TransformConfig(
                10, 
                {
                    0: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    1: lambda k: k + 96,
                    2: lambda k: ((k << 1) | (k >> 7)) & 0xFF,
                    3: lambda k: ((k >> 4) | (k << 4)) & 0xFF,
                    4: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    5: lambda k: k + 149,
                    6: lambda k: ((k >> 5) | (k << 3)) & 0xFF,
                    7: lambda k: ((k << 4) | (k >> 4)) & 0xFF,
                    8: lambda k: k - 23,
                    9: lambda k: k + 96,
                }
            ),
        ),

]
