
# This file was *autogenerated* from the file des-8.sage
from sage.all_cmdline import *   # import sage library

_sage_const_3 = Integer(3); _sage_const_2 = Integer(2); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_7 = Integer(7); _sage_const_6 = Integer(6); _sage_const_5 = Integer(5); _sage_const_4 = Integer(4); _sage_const_9 = Integer(9); _sage_const_8 = Integer(8); _sage_const_55 = Integer(55); _sage_const_31 = Integer(31); _sage_const_28 = Integer(28); _sage_const_29 = Integer(29); _sage_const_59 = Integer(59); _sage_const_30 = Integer(30); _sage_const_22 = Integer(22); _sage_const_23 = Integer(23); _sage_const_20 = Integer(20); _sage_const_21 = Integer(21); _sage_const_26 = Integer(26); _sage_const_27 = Integer(27); _sage_const_24 = Integer(24); _sage_const_25 = Integer(25); _sage_const_40 = Integer(40); _sage_const_41 = Integer(41); _sage_const_42 = Integer(42); _sage_const_43 = Integer(43); _sage_const_44 = Integer(44); _sage_const_63 = Integer(63); _sage_const_60 = Integer(60); _sage_const_47 = Integer(47); _sage_const_48 = Integer(48); _sage_const_49 = Integer(49); _sage_const_54 = Integer(54); _sage_const_52 = Integer(52); _sage_const_58 = Integer(58); _sage_const_37 = Integer(37); _sage_const_36 = Integer(36); _sage_const_45 = Integer(45); _sage_const_53 = Integer(53); _sage_const_64 = Integer(64); _sage_const_32 = Integer(32); _sage_const_13 = Integer(13); _sage_const_12 = Integer(12); _sage_const_11 = Integer(11); _sage_const_10 = Integer(10); _sage_const_17 = Integer(17); _sage_const_16 = Integer(16); _sage_const_15 = Integer(15); _sage_const_14 = Integer(14); _sage_const_57 = Integer(57); _sage_const_62 = Integer(62); _sage_const_33 = Integer(33); _sage_const_18 = Integer(18); _sage_const_35 = Integer(35); _sage_const_34 = Integer(34); _sage_const_51 = Integer(51); _sage_const_50 = Integer(50); _sage_const_39 = Integer(39); _sage_const_46 = Integer(46); _sage_const_38 = Integer(38); _sage_const_61 = Integer(61); _sage_const_56 = Integer(56); _sage_const_19 = Integer(19); _sage_const_1000 = Integer(1000)###############
# Lance test
is_test = False
###############

# DES-8

SBOX = []

SBOX.append([_sage_const_14 ,  _sage_const_4 , _sage_const_13 ,  _sage_const_1 ,  _sage_const_2 , _sage_const_15 , _sage_const_11 ,  _sage_const_8 ,  _sage_const_3 , _sage_const_10 ,  _sage_const_6 , _sage_const_12 ,  _sage_const_5 ,  _sage_const_9 ,  _sage_const_0 ,  _sage_const_7 ,
              _sage_const_0 , _sage_const_15 ,  _sage_const_7 ,  _sage_const_4 , _sage_const_14 ,  _sage_const_2 , _sage_const_13 ,  _sage_const_1 , _sage_const_10 ,  _sage_const_6 , _sage_const_12 , _sage_const_11 ,  _sage_const_9 ,  _sage_const_5 ,  _sage_const_3 ,  _sage_const_8 ,
              _sage_const_4 ,  _sage_const_1 , _sage_const_14 ,  _sage_const_8 , _sage_const_13 ,  _sage_const_6 ,  _sage_const_2 , _sage_const_11 , _sage_const_15 , _sage_const_12 ,  _sage_const_9 ,  _sage_const_7 ,  _sage_const_3 , _sage_const_10 ,  _sage_const_5 ,  _sage_const_0 ,
             _sage_const_15 , _sage_const_12 ,  _sage_const_8 ,  _sage_const_2 ,  _sage_const_4 ,  _sage_const_9 ,  _sage_const_1 ,  _sage_const_7 ,  _sage_const_5 , _sage_const_11 ,  _sage_const_3 , _sage_const_14 , _sage_const_10 ,  _sage_const_0 ,  _sage_const_6 , _sage_const_13 ])

SBOX.append([_sage_const_15 ,  _sage_const_1 ,  _sage_const_8 , _sage_const_14 ,  _sage_const_6 , _sage_const_11 ,  _sage_const_3 ,  _sage_const_4 ,  _sage_const_9 ,  _sage_const_7 ,  _sage_const_2 , _sage_const_13 , _sage_const_12 ,  _sage_const_0 ,  _sage_const_5 , _sage_const_10 ,
              _sage_const_3 , _sage_const_13 ,  _sage_const_4 ,  _sage_const_7 , _sage_const_15 ,  _sage_const_2 ,  _sage_const_8 , _sage_const_14 , _sage_const_12 ,  _sage_const_0 ,  _sage_const_1 , _sage_const_10 ,  _sage_const_6 ,  _sage_const_9 , _sage_const_11 ,  _sage_const_5 ,
              _sage_const_0 , _sage_const_14 ,  _sage_const_7 , _sage_const_11 , _sage_const_10 ,  _sage_const_4 , _sage_const_13 ,  _sage_const_1 ,  _sage_const_5 ,  _sage_const_8 , _sage_const_12 ,  _sage_const_6 ,  _sage_const_9 ,  _sage_const_3 ,  _sage_const_2 , _sage_const_15 ,
             _sage_const_13 ,  _sage_const_8 , _sage_const_10 ,  _sage_const_1 ,  _sage_const_3 , _sage_const_15 ,  _sage_const_4 ,  _sage_const_2 , _sage_const_11 ,  _sage_const_6 ,  _sage_const_7 , _sage_const_12 ,  _sage_const_0 ,  _sage_const_5 , _sage_const_14 ,  _sage_const_9 ])

SBOX.append([_sage_const_10 ,  _sage_const_0 ,  _sage_const_9 , _sage_const_14 ,  _sage_const_6 ,  _sage_const_3 , _sage_const_15 ,  _sage_const_5 ,  _sage_const_1 , _sage_const_13 , _sage_const_12 ,  _sage_const_7 , _sage_const_11 ,  _sage_const_4 ,  _sage_const_2 ,  _sage_const_8 ,
             _sage_const_13 ,  _sage_const_7 ,  _sage_const_0 ,  _sage_const_9 ,  _sage_const_3 ,  _sage_const_4 ,  _sage_const_6 , _sage_const_10 ,  _sage_const_2 ,  _sage_const_8 ,  _sage_const_5 , _sage_const_14 , _sage_const_12 , _sage_const_11 , _sage_const_15 ,  _sage_const_1 ,
             _sage_const_13 ,  _sage_const_6 ,  _sage_const_4 ,  _sage_const_9 ,  _sage_const_8 , _sage_const_15 ,  _sage_const_3 ,  _sage_const_0 , _sage_const_11 ,  _sage_const_1 ,  _sage_const_2 , _sage_const_12 ,  _sage_const_5 , _sage_const_10 , _sage_const_14 ,  _sage_const_7 ,
              _sage_const_1 , _sage_const_10 , _sage_const_13 ,  _sage_const_0 ,  _sage_const_6 ,  _sage_const_9 ,  _sage_const_8 ,  _sage_const_7 ,  _sage_const_4 , _sage_const_15 , _sage_const_14 ,  _sage_const_3 , _sage_const_11 ,  _sage_const_5 ,  _sage_const_2 , _sage_const_12 ])

SBOX.append([ _sage_const_7 , _sage_const_13 , _sage_const_14 ,  _sage_const_3 ,  _sage_const_0 ,  _sage_const_6 ,  _sage_const_9 , _sage_const_10 ,  _sage_const_1 ,  _sage_const_2 ,  _sage_const_8 ,  _sage_const_5 , _sage_const_11 , _sage_const_12 ,  _sage_const_4 , _sage_const_15 ,
             _sage_const_13 ,  _sage_const_8 , _sage_const_11 ,  _sage_const_5 ,  _sage_const_6 , _sage_const_15 ,  _sage_const_0 ,  _sage_const_3 ,  _sage_const_4 ,  _sage_const_7 ,  _sage_const_2 , _sage_const_12 ,  _sage_const_1 , _sage_const_10 , _sage_const_14 ,  _sage_const_9 ,
             _sage_const_10 ,  _sage_const_6 ,  _sage_const_9 ,  _sage_const_0 , _sage_const_12 , _sage_const_11 ,  _sage_const_7 , _sage_const_13 , _sage_const_15 ,  _sage_const_1 ,  _sage_const_3 , _sage_const_14 ,  _sage_const_5 ,  _sage_const_2 ,  _sage_const_8 ,  _sage_const_4 ,
              _sage_const_3 , _sage_const_15 ,  _sage_const_0 ,  _sage_const_6 , _sage_const_10 ,  _sage_const_1 , _sage_const_13 ,  _sage_const_8 ,  _sage_const_9 ,  _sage_const_4 ,  _sage_const_5 , _sage_const_11 , _sage_const_12 ,  _sage_const_7 ,  _sage_const_2 , _sage_const_14 ])

SBOX.append([ _sage_const_2 , _sage_const_12 ,  _sage_const_4 ,  _sage_const_1 ,  _sage_const_7 , _sage_const_10 , _sage_const_11 ,  _sage_const_6 ,  _sage_const_8 ,  _sage_const_5 ,  _sage_const_3 , _sage_const_15 , _sage_const_13 ,  _sage_const_0 , _sage_const_14 ,  _sage_const_9 ,
             _sage_const_14 , _sage_const_11 ,  _sage_const_2 , _sage_const_12 ,  _sage_const_4 ,  _sage_const_7 , _sage_const_13 ,  _sage_const_1 ,  _sage_const_5 ,  _sage_const_0 , _sage_const_15 , _sage_const_10 ,  _sage_const_3 ,  _sage_const_9 ,  _sage_const_8 ,  _sage_const_6 ,
              _sage_const_4 ,  _sage_const_2 ,  _sage_const_1 , _sage_const_11 , _sage_const_10 , _sage_const_13 ,  _sage_const_7 ,  _sage_const_8 , _sage_const_15 ,  _sage_const_9 , _sage_const_12 ,  _sage_const_5 ,  _sage_const_6 ,  _sage_const_3 ,  _sage_const_0 , _sage_const_14 ,
             _sage_const_11 ,  _sage_const_8 , _sage_const_12 ,  _sage_const_7 ,  _sage_const_1 , _sage_const_14 ,  _sage_const_2 , _sage_const_13 ,  _sage_const_6 , _sage_const_15 ,  _sage_const_0 ,  _sage_const_9 , _sage_const_10 ,  _sage_const_4 ,  _sage_const_5 ,  _sage_const_3 ])

SBOX.append([_sage_const_12 ,  _sage_const_1 , _sage_const_10 , _sage_const_15 ,  _sage_const_9 ,  _sage_const_2 ,  _sage_const_6 ,  _sage_const_8 ,  _sage_const_0 , _sage_const_13 ,  _sage_const_3 ,  _sage_const_4 , _sage_const_14 ,  _sage_const_7 ,  _sage_const_5 , _sage_const_11 ,
             _sage_const_10 , _sage_const_15 ,  _sage_const_4 ,  _sage_const_2 ,  _sage_const_7 , _sage_const_12 ,  _sage_const_9 ,  _sage_const_5 ,  _sage_const_6 ,  _sage_const_1 , _sage_const_13 , _sage_const_14 ,  _sage_const_0 , _sage_const_11 ,  _sage_const_3 ,  _sage_const_8 ,
              _sage_const_9 , _sage_const_14 , _sage_const_15 ,  _sage_const_5 ,  _sage_const_2 ,  _sage_const_8 , _sage_const_12 ,  _sage_const_3 ,  _sage_const_7 ,  _sage_const_0 ,  _sage_const_4 , _sage_const_10 ,  _sage_const_1 , _sage_const_13 , _sage_const_11 ,  _sage_const_6 ,
              _sage_const_4 ,  _sage_const_3 ,  _sage_const_2 , _sage_const_12 ,  _sage_const_9 ,  _sage_const_5 , _sage_const_15 , _sage_const_10 , _sage_const_11 , _sage_const_14 ,  _sage_const_1 ,  _sage_const_7 ,  _sage_const_6 ,  _sage_const_0 ,  _sage_const_8 , _sage_const_13 ])

SBOX.append([ _sage_const_4 , _sage_const_11 ,  _sage_const_2 , _sage_const_14 , _sage_const_15 ,  _sage_const_0 ,  _sage_const_8 , _sage_const_13 ,  _sage_const_3 , _sage_const_12 ,  _sage_const_9 ,  _sage_const_7 ,  _sage_const_5 , _sage_const_10 ,  _sage_const_6 ,  _sage_const_1 ,
             _sage_const_13 ,  _sage_const_0 , _sage_const_11 ,  _sage_const_7 ,  _sage_const_4 ,  _sage_const_9 ,  _sage_const_1 , _sage_const_10 , _sage_const_14 ,  _sage_const_3 ,  _sage_const_5 , _sage_const_12 ,  _sage_const_2 , _sage_const_15 ,  _sage_const_8 ,  _sage_const_6 ,
              _sage_const_1 ,  _sage_const_4 , _sage_const_11 , _sage_const_13 , _sage_const_12 ,  _sage_const_3 ,  _sage_const_7 , _sage_const_14 , _sage_const_10 , _sage_const_15 ,  _sage_const_6 ,  _sage_const_8 ,  _sage_const_0 ,  _sage_const_5 ,  _sage_const_9 ,  _sage_const_2 ,
              _sage_const_6 , _sage_const_11 , _sage_const_13 ,  _sage_const_8 ,  _sage_const_1 ,  _sage_const_4 , _sage_const_10 ,  _sage_const_7 ,  _sage_const_9 ,  _sage_const_5 ,  _sage_const_0 , _sage_const_15 , _sage_const_14 ,  _sage_const_2 ,  _sage_const_3 , _sage_const_12 ])

SBOX.append([_sage_const_13 ,  _sage_const_2 ,  _sage_const_8 ,  _sage_const_4 ,  _sage_const_6 , _sage_const_15 , _sage_const_11 ,  _sage_const_1 , _sage_const_10 ,  _sage_const_9 ,  _sage_const_3 , _sage_const_14 ,  _sage_const_5 ,  _sage_const_0 , _sage_const_12 ,  _sage_const_7 ,
              _sage_const_1 , _sage_const_15 , _sage_const_13 ,  _sage_const_8 , _sage_const_10 ,  _sage_const_3 ,  _sage_const_7 ,  _sage_const_4 , _sage_const_12 ,  _sage_const_5 ,  _sage_const_6 , _sage_const_11 ,  _sage_const_0 , _sage_const_14 ,  _sage_const_9 ,  _sage_const_2 ,
              _sage_const_7 , _sage_const_11 ,  _sage_const_4 ,  _sage_const_1 ,  _sage_const_9 , _sage_const_12 , _sage_const_14 ,  _sage_const_2 ,  _sage_const_0 ,  _sage_const_6 , _sage_const_10 , _sage_const_13 , _sage_const_15 ,  _sage_const_3 ,  _sage_const_5 ,  _sage_const_8 ,
              _sage_const_2 ,  _sage_const_1 , _sage_const_14 ,  _sage_const_7 ,  _sage_const_4 , _sage_const_10 ,  _sage_const_8 , _sage_const_13 , _sage_const_15 , _sage_const_12 ,  _sage_const_9 ,  _sage_const_0 ,  _sage_const_3 ,  _sage_const_5 ,  _sage_const_6 , _sage_const_11 ])

def key_schedule(keyByteList):

    PC1 = [_sage_const_57 , _sage_const_49 , _sage_const_41 , _sage_const_33 , _sage_const_25 , _sage_const_17 ,  _sage_const_9 ,
            _sage_const_1 , _sage_const_58 , _sage_const_50 , _sage_const_42 , _sage_const_34 , _sage_const_26 , _sage_const_18 ,
           _sage_const_10 ,  _sage_const_2 , _sage_const_59 , _sage_const_51 , _sage_const_43 , _sage_const_35 , _sage_const_27 ,
           _sage_const_19 , _sage_const_11 ,  _sage_const_3 , _sage_const_60 , _sage_const_52 , _sage_const_44 , _sage_const_36 ,
           _sage_const_63 , _sage_const_55 , _sage_const_47 , _sage_const_39 , _sage_const_31 , _sage_const_23 , _sage_const_15 ,
            _sage_const_7 , _sage_const_62 , _sage_const_54 , _sage_const_46 , _sage_const_38 , _sage_const_30 , _sage_const_22 ,
           _sage_const_14 ,  _sage_const_6 , _sage_const_61 , _sage_const_53 , _sage_const_45 , _sage_const_37 , _sage_const_29 ,
           _sage_const_21 , _sage_const_13 ,  _sage_const_5 , _sage_const_28 , _sage_const_20 , _sage_const_12 ,  _sage_const_4 ]

    PC2= [_sage_const_14 , _sage_const_17 , _sage_const_11 , _sage_const_24 ,  _sage_const_1 ,  _sage_const_5 ,  _sage_const_3 , _sage_const_28 ,
    	  _sage_const_15 ,  _sage_const_6 , _sage_const_21 , _sage_const_10 , _sage_const_23 , _sage_const_19 , _sage_const_12 ,  _sage_const_4 ,
    	  _sage_const_26 ,  _sage_const_8 , _sage_const_16 ,  _sage_const_7 , _sage_const_27 , _sage_const_20 , _sage_const_13 ,  _sage_const_2 ,
    	  _sage_const_41 , _sage_const_52 , _sage_const_31 , _sage_const_37 , _sage_const_47 , _sage_const_55 , _sage_const_30 , _sage_const_40 ,
    	  _sage_const_51 , _sage_const_45 , _sage_const_33 , _sage_const_48 , _sage_const_44 , _sage_const_49 , _sage_const_39 , _sage_const_56 ,
    	  _sage_const_34 , _sage_const_53 , _sage_const_46 , _sage_const_42 , _sage_const_50 , _sage_const_36 , _sage_const_29 , _sage_const_32 ]

    new_key = []
    for i in range(len(PC1)):
        new_key.append(keyByteList[PC1[i] - _sage_const_1 ])

    C0 = new_key[_sage_const_0  : len(new_key) / _sage_const_2 ]
    D0 = new_key[len(new_key) / _sage_const_2  : len(new_key)]

    def shift(shift_list, n):
        n = n % len(shift_list)
        return shift_list[n:] + shift_list[:n]

    Cn = []
    Dn = []
    Shift_Dis = [_sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 ] # 8 tour in the place of 16
    Shift_Pos = _sage_const_0 
    for i in range(_sage_const_8 ):
        Shift_Pos += Shift_Dis[i]
        Cn.append(shift(C0, Shift_Pos))
        Dn.append(shift(D0, Shift_Pos))

    K = []
    for i in range(_sage_const_8 ): # 8 tour in the place of 16
        tmp = Cn[i] + Dn[i]
        tmp_K = []
        for j in range(len(PC2)):
            tmp_K.append(tmp[PC2[j] - _sage_const_1 ])

        K.append(tmp_K)

    return K

def expend(R32):
    E = [_sage_const_32 ,  _sage_const_1 ,  _sage_const_2 ,  _sage_const_3 ,  _sage_const_4 ,  _sage_const_5 ,
          _sage_const_4 ,  _sage_const_5 ,  _sage_const_6 ,  _sage_const_7 ,  _sage_const_8 ,  _sage_const_9 ,
          _sage_const_8 ,  _sage_const_9 , _sage_const_10 , _sage_const_11 , _sage_const_12 , _sage_const_13 ,
         _sage_const_12 , _sage_const_13 , _sage_const_14 , _sage_const_15 , _sage_const_16 , _sage_const_17 ,
         _sage_const_16 , _sage_const_17 , _sage_const_18 , _sage_const_19 , _sage_const_20 , _sage_const_21 ,
         _sage_const_20 , _sage_const_21 , _sage_const_22 , _sage_const_23 , _sage_const_24 , _sage_const_25 ,
         _sage_const_24 , _sage_const_25 , _sage_const_26 , _sage_const_27 , _sage_const_28 , _sage_const_29 ,
         _sage_const_28 , _sage_const_29 , _sage_const_30 , _sage_const_31 , _sage_const_32 ,  _sage_const_1 ]
    R48 = []
    for i in range(len(E)):
        R48.append(R32[E[i] - _sage_const_1 ])
    return R48

def f(R, Kf):
    R48 = expend(R)
    pls = [] # result for K + E(R)
    for i in range(_sage_const_48 ):
        tmp0 = (Kf[i] + R48[i]) % _sage_const_2 
        pls.append(tmp0)

    def f6to4(B, thisSbox):
        row = B[_sage_const_0 ] * _sage_const_2  + B[-_sage_const_1 ]
        col = B[_sage_const_1 ] * (_sage_const_2 **_sage_const_3 ) + B[_sage_const_2 ] * (_sage_const_2 **_sage_const_2 ) + B[_sage_const_3 ] * _sage_const_2  + B[_sage_const_4 ]
        res = thisSbox[row * _sage_const_16  + col].digits(_sage_const_2 )
        return res[::-_sage_const_1 ]

    res_sbox = []
    for i in range(_sage_const_8 ):
        B = pls[_sage_const_6  * i : _sage_const_6  * (i+_sage_const_1 )]
        tmp1 = f6to4(B, SBOX[i])
        tmp1 = [_sage_const_0  for i in range(_sage_const_4  - len(tmp1))] + tmp1
        res_sbox += tmp1

    P = [_sage_const_16 ,  _sage_const_7 , _sage_const_20 , _sage_const_21 , _sage_const_29 , _sage_const_12 , _sage_const_28 , _sage_const_17 ,
          _sage_const_1 , _sage_const_15 , _sage_const_23 , _sage_const_26 ,  _sage_const_5 , _sage_const_18 , _sage_const_31 , _sage_const_10 ,
          _sage_const_2 ,  _sage_const_8 , _sage_const_24 , _sage_const_14 , _sage_const_32 , _sage_const_27 ,  _sage_const_3 ,  _sage_const_9 ,
         _sage_const_19 , _sage_const_13 , _sage_const_30 ,  _sage_const_6 , _sage_const_22 , _sage_const_11 ,  _sage_const_4 , _sage_const_25 ]

    res_f = []
    for i in range(len(P)):
        res_f.append(res_sbox[P[i] - _sage_const_1 ])

    return res_f

def DES8(M, Kn):
    L0 = M[_sage_const_0  : len(M) / _sage_const_2 ]
    R0 = M[len(M) / _sage_const_2  : len(M)]

    Ln = [L0]
    Rn = [R0]
    for i in range(_sage_const_8 ): # # 8 tour in the place of 16
        Ln.append(Rn[-_sage_const_1 ])
        resf = f(Rn[-_sage_const_1 ], Kn[i])
        new_R = []
        L_tmp = Ln[-_sage_const_2 ]
        for j in range (len(L0)):
            tmp2 = (L_tmp[j] + resf[j]) % _sage_const_2 
            new_R.append(tmp2)
        Rn.append(new_R)

    Ln = Ln[_sage_const_1 :len(Ln)]
    Rn = Rn[_sage_const_1 :len(Rn)]

    LastRL = Rn[-_sage_const_1 ] + Ln[-_sage_const_1 ]
    return LastRL

if(is_test):
    load('./test/test_vectors.sage')
    print "Q1: %s\n" % (test_vectors())

######################
# Question 2
######################

# la fonction inverse
def IntToList(x, n):
  L = ZZ(x).digits(_sage_const_2 , padto=n) #L est constitue d'entiers
  L.reverse()
  L = [GF(_sage_const_2 )(el) for el in L] # L est constitue d'elements de GF(2)
  return L

# L[alpha, beta] = Card{x in [0, 2^6], <alpha, x> + <beta, S5(x)> = 0}
def Card_L():
    L = matrix(_sage_const_64 , _sage_const_16 )
    for alpha in range (_sage_const_64 ): # alpha in [0, 2^6]
        a_list = IntToList(alpha, _sage_const_6 )
        for beta in range (_sage_const_16 ): # beta in [0, 2^4]
            b_list = IntToList(beta, _sage_const_4 )
            amount = _sage_const_0 
            for x in range (_sage_const_64 ): # x in [0, 2^6]
                x_list  = IntToList(x, _sage_const_6 )
                sx_list = IntToList(SBOX[_sage_const_4 ][x], _sage_const_4 )
                atmp = [a_list[i] * x_list[i]  for i in range (len(a_list))]
                ax   = sum(atmp)
                btmp = [b_list[i] * sx_list[i] for i in range (len(b_list))]
                bsx  = sum(btmp)
                if (ax + bsx  == _sage_const_0 ):
                    amount += _sage_const_1 
            L[alpha, beta] = amount
    return L

if(is_test):
    L_Q2 = Card_L()
    print "Q2: L="
    for i in range(_sage_const_64 ):
        print "       %s" % (L_Q2[i])
    print ""

###########################
# Question 3
###########################

# X[16] = Y[2] + Y[7] + Y[13] + Y[24]

def proba_XY(K):
    X = [randint(GF(_sage_const_2 ) (_sage_const_0 ), _sage_const_1 ) for x in range(_sage_const_32 )]
    Y = f(X, K)
    right = (Y[_sage_const_2 ] + Y[_sage_const_7 ] + Y[_sage_const_13 ] +Y[_sage_const_24 ]) % _sage_const_2 
    if(X[_sage_const_16 ] == right):
        return True
    else:
        return False

if(is_test):
    key = [randint(GF(_sage_const_2 ) (_sage_const_0 ), _sage_const_1 ) for x in range(_sage_const_48 )]
    nb_equal = _sage_const_0 
    total = _sage_const_1000 
    for i in range(total):
        if(proba_XY(key)):
            nb_equal += _sage_const_1 

    print("Q3: Proba = %s\n") % ((nb_equal/total).n())

###########################
# Question 4
###########################

# L0[2] + L0[7] + L0[13] + L0[24] + R0[16] + \
# R3[2] + R3[7] + R3[13] + R3[24] + L3[16] = 0

def proba_LR(M, sk):
    sk_LR = key_schedule(sk)
    L0 = M[_sage_const_0  : len(M) / _sage_const_2 ]
    R0 = M[len(M) / _sage_const_2  : len(M)]

    Ln = [L0]
    Rn = [R0]
    for i in range(_sage_const_3 ):
        Ln.append(Rn[-_sage_const_1 ])
        resf = f(Rn[-_sage_const_1 ], sk_LR[i])
        new_R = []
        L_tmp = Ln[-_sage_const_2 ]
        for j in range (len(L0)):
            tmp2 = (L_tmp[j] + resf[j]) % _sage_const_2 
            new_R.append(tmp2)
        Rn.append(new_R)

    left = (Ln[_sage_const_0 ][_sage_const_2 ] + Ln[_sage_const_0 ][_sage_const_7 ] + Ln[_sage_const_0 ][_sage_const_13 ] + Ln[_sage_const_0 ][_sage_const_24 ] + Rn[_sage_const_0 ][_sage_const_16 ] + \
            Rn[_sage_const_3 ][_sage_const_2 ] + Rn[_sage_const_3 ][_sage_const_7 ] + Rn[_sage_const_3 ][_sage_const_13 ] + Rn[_sage_const_3 ][_sage_const_24 ] + Ln[_sage_const_3 ][_sage_const_16 ]) % _sage_const_2 
    if(left == _sage_const_0 ):
        return True
    else:
        return False
if(is_test):
    nb_equal = _sage_const_0 
    total = _sage_const_1000 
    key = [randint(GF(_sage_const_2 ) (_sage_const_0 ), _sage_const_1 ) for x in range(_sage_const_64 )]
    for i in range(total):
        M = [randint(_sage_const_0 , _sage_const_1 ) for m in range (_sage_const_64 )]
        if(proba_LR(M, key)):
            nb_equal += _sage_const_1 

    print("Q4: Proba = %s\n") % ((nb_equal/total).n())

###########################
# Question 5
###########################

# R1 = R1*
# L1 != L1*
# L1 + L1* = 0(alpha)(beta)00000000000000000000000000000
# Different bit number = 1 or 2

def DES_L1_R1(key, L_or_R):
    # On genere directement L et R du 1er tour, message original ne sert rien
    R1 = [randint(_sage_const_0 , _sage_const_1 ) for m in range (_sage_const_32 )]
    L_1_1 = [randint(_sage_const_0 , _sage_const_1 ) for m in range (_sage_const_32 )]
    L_2_1 = copy(L_1_1)
    if (randint(_sage_const_1 , _sage_const_2 ) == _sage_const_1 ): # une difference
        pos = randint(_sage_const_1 , _sage_const_2 )
        L_2_1[pos]  = (L_2_1[pos] + _sage_const_1 ) % _sage_const_2 
    else:
        L_2_1[_sage_const_1 ] = (L_2_1[_sage_const_1 ] + _sage_const_1 ) % _sage_const_2 
        L_2_1[_sage_const_2 ] = (L_2_1[_sage_const_2 ] + _sage_const_1 ) % _sage_const_2 

    Ln_1 = [L_1_1]
    Ln_2 = [L_2_1]
    Rn_1 = [R1]
    Rn_2 = [R1]

    for i in range(_sage_const_1 , _sage_const_5 ): # Classic DES 16
        Ln_1.append(Rn_1[-_sage_const_1 ])
        Ln_2.append(Rn_2[-_sage_const_1 ])
        resf_1 = f(Rn_1[-_sage_const_1 ], key)
        resf_2 = f(Rn_2[-_sage_const_1 ], key)
        new_R1 = []
        new_R2 = []
        for j in range(len(L_1_1)):
            tmp2 = (Ln_1[-_sage_const_2 ][j] + resf_1[j]) % _sage_const_2 
            new_R1.append(tmp2)
            tmp2 = (Ln_2[-_sage_const_2 ][j] + resf_2[j]) % _sage_const_2 
            new_R2.append(tmp2)
        Rn_1.append(new_R1)
        Rn_2.append(new_R2)

    list_diff = []
    if L_or_R == 'L':
        for i in range(len(Ln_1[-_sage_const_1 ])):
            if Ln_1[-_sage_const_1 ][i] != Ln_2[-_sage_const_1 ][i]:
                list_diff.append(i)
    if L_or_R == 'R':
        for i in range(len(Rn_1[-_sage_const_1 ])):
            if Rn_1[-_sage_const_1 ][i] != Rn_2[-_sage_const_1 ][i]:
                list_diff.append(i)
    return list_diff

if(is_test):
    key = [randint(GF(_sage_const_2 ) (_sage_const_0 ), _sage_const_1 ) for x in range(_sage_const_48 )]
    print ("Q5:\nLes indices differents entre L4 et L4* sont: %s\nLes indices "
           "differents entre R4 et R4* sont: %s\nListe vide = Deux les deux "
           "sont pareils\n") % (DES_L1_R1(key, 'L'), DES_L1_R1(key, 'R'))

###########################
# Question 6
###########################

# R7[2] + R7[7] + R7[13] + R7[24] + L7[16] + \
# R7*[2] + R7*[7] + R7*[13] + R7*[24] + L7*[16] = 0

def proba_LR_7(key):
    # On genere directement L et R du 1er tour, message original ne sert rien
    R1 = [randint(_sage_const_0 , _sage_const_1 ) for m in range (_sage_const_32 )]
    L_1_1 = [randint(_sage_const_0 , _sage_const_1 ) for m in range (_sage_const_32 )]
    L_2_1 = copy(L_1_1)
    if (randint(_sage_const_1 , _sage_const_2 ) == _sage_const_1 ): # une difference
        pos = randint(_sage_const_1 , _sage_const_2 )
        L_2_1[pos]  = (L_2_1[pos] + _sage_const_1 ) % _sage_const_2 
    else:
        L_2_1[_sage_const_1 ] = (L_2_1[_sage_const_1 ] + _sage_const_1 ) % _sage_const_2 
        L_2_1[_sage_const_2 ] = (L_2_1[_sage_const_2 ] + _sage_const_1 ) % _sage_const_2 

    Ln_1 = [L_1_1]
    Ln_2 = [L_2_1]
    Rn_1 = [R1]
    Rn_2 = [R1]

    for i in range(_sage_const_1 , _sage_const_7 ): # Recuperer L7 et R7 des deux messages
        Ln_1.append(Rn_1[-_sage_const_1 ])
        Ln_2.append(Rn_2[-_sage_const_1 ])
        resf_1 = f(Rn_1[-_sage_const_1 ], key)
        resf_2 = f(Rn_2[-_sage_const_1 ], key)
        new_R1 = []
        new_R2 = []
        for j in range(len(R1)):
            tmp = (Ln_1[-_sage_const_2 ][j] + resf_1[j]) % _sage_const_2 
            new_R1.append(tmp)
            tmp = (Ln_2[-_sage_const_2 ][j] + resf_2[j]) % _sage_const_2 
            new_R2.append(tmp)
        Rn_1.append(new_R1)
        Rn_2.append(new_R2)

    left = (Rn_1[_sage_const_6 ][_sage_const_2 ] + Rn_1[_sage_const_6 ][_sage_const_7 ] + Rn_1[_sage_const_6 ][_sage_const_13 ] + Rn_1[_sage_const_6 ][_sage_const_24 ] + \
            Ln_1[_sage_const_6 ][_sage_const_16 ] + \
            Rn_2[_sage_const_6 ][_sage_const_2 ] + Rn_2[_sage_const_6 ][_sage_const_7 ] + Rn_2[_sage_const_6 ][_sage_const_13 ] + Rn_2[_sage_const_6 ][_sage_const_24 ] + \
            Ln_2[_sage_const_6 ][_sage_const_16 ]) % _sage_const_2 

    if left == _sage_const_0 :
        return True
    else:
        return False

if(is_test):
    nb_equal = _sage_const_0 
    total = _sage_const_1000 
    key = [randint(GF(_sage_const_2 ) (_sage_const_0 ), _sage_const_1 ) for x in range(_sage_const_48 )]
    for i in range(total):
        if(proba_LR_7(key)):
            nb_equal += _sage_const_1 

    print("Q6: Proba = %s\n") % ((nb_equal/total).n())

###########################
# Question 7
###########################

def find_key(msg_cipher, part_key):
    msg_1 = msg_cipher[_sage_const_0 ]
    msg_2 = msg_cipher[_sage_const_1 ]

    # R7 = L8, donc on caluler la somme sauf L7/L7* avec R7/R7*
    without_L7 = (msg_1[_sage_const_34 ] + msg_1[_sage_const_39 ] + msg_1[_sage_const_45 ] + msg_1[_sage_const_56 ] + \
                  msg_2[_sage_const_34 ] + msg_2[_sage_const_39 ] + msg_2[_sage_const_45 ] + msg_2[_sage_const_56 ]) % _sage_const_2 

    L7_1_16 = (f(msg_1[_sage_const_32 :], part_key)[_sage_const_16 ] + msg_1[_sage_const_16 ]) % _sage_const_2 
    L7_2_16 = (f(msg_2[_sage_const_32 :], part_key)[_sage_const_16 ] + msg_2[_sage_const_16 ]) % _sage_const_2 

    # Tester si 0
    if ((without_L7 + L7_1_16 + L7_2_16) % _sage_const_2 ) == _sage_const_0 :
        return True # proba = 0
    else:
        return False

def Int2List(x, n):
  L = ZZ(x).digits(_sage_const_2 , padto=n) #L est constitue d'entiers
  L.reverse()
  L = [(el) for el in L] # L est constitue d'elements pas de GF(2)
  return L

def guess_bf_K8(couples): #  brute force
    right = _sage_const_0 
    k8 = []
    for x in range(_sage_const_64 ):

        key = Int2List(x, _sage_const_6 )
        key += [_sage_const_0  for x in range (_sage_const_42 )]
        nb_equal = _sage_const_0 
        for nb_couple in range(len(couples)):
            if find_key(couples[nb_couple], key):
                nb_equal += _sage_const_1 
        proba = (nb_equal/len(couples))
        if (proba > right):
            right = proba.n()
            k8 = key[:_sage_const_6 ]
    return k8, right


if(is_test):
    load('./test/question7.sage')

    K8_6, proba = guess_bf_K8(Couples)
    print "Q7: Part of K8 found %s\n" % (K8_6)

###########################
# Question 8
###########################

# Generation de m et M
def gen_M_change(m):

    M = []
    # Generation des m* en modifier 8, 16, 20, 30, 33, 34
    for i in range(_sage_const_64 ):
        bit_change = Int2List(i, _sage_const_6 )
        msg_tmp = copy(m)
        msg_tmp[_sage_const_8 ] = (msg_tmp[_sage_const_8 ] + bit_change[_sage_const_0 ]) % _sage_const_2 
        msg_tmp[_sage_const_16 ] = (msg_tmp[_sage_const_16 ] + bit_change[_sage_const_1 ]) % _sage_const_2 
        msg_tmp[_sage_const_22 ] = (msg_tmp[_sage_const_22 ] + bit_change[_sage_const_2 ]) % _sage_const_2 
        msg_tmp[_sage_const_30 ] = (msg_tmp[_sage_const_30 ] + bit_change[_sage_const_3 ]) % _sage_const_2 
        msg_tmp[_sage_const_33 ] = (msg_tmp[_sage_const_33 ] + bit_change[_sage_const_4 ]) % _sage_const_2 
        msg_tmp[_sage_const_34 ] = (msg_tmp[_sage_const_34 ] + bit_change[_sage_const_5 ]) % _sage_const_2 
        M.append(msg_tmp)

    return M

# First tour of DES-8
def one_tour(M, Key):
    L0 = M[_sage_const_0  : len(M) / _sage_const_2 ]
    R0 = M[len(M) / _sage_const_2  : len(M)]

    Ln = [L0]
    Rn = [R0]
    for i in range(_sage_const_1 ):
        Ln.append(Rn[-_sage_const_1 ])
        resf = f(Rn[-_sage_const_1 ], Key)
        new_R = []
        L_tmp = Ln[-_sage_const_2 ]
        for j in range (len(L0)):
            tmp2 = (L_tmp[j] + resf[j]) % _sage_const_2 
            new_R.append(tmp2)
        Rn.append(new_R)

    LastRL = Ln[-_sage_const_1 ] + Rn[-_sage_const_1 ]
    return LastRL

def gen_couple_M(M, K1_6_bit):
    couple_msg = []
    m_Star = []
    key = K1_6_bit + [_sage_const_0  for p in range(_sage_const_42 )]
    for k in range(_sage_const_64 ):
        c1 = one_tour(M[k], key)
        for l in range(k + _sage_const_1 , _sage_const_64 ):
            c2 = one_tour(M[l], key)
            if ((c1[_sage_const_32 :] == c2[_sage_const_32 :]) and (c1[:_sage_const_32 ] != c2[:_sage_const_32 ])):
                # [8], [16], [22], [30] changes disapeared
                # at least one of [33], [34] is different
                couple_msg.append([M[k], M[l]])

    # # Now we have 96 couples of message
    # # Some m is already included in m*, we delete them
    # double = []
    # for i in range(0, len(couple_msg), 3):
    #     for j in range(0, len(couple_msg)):
    #         if (couple_msg[i][0] == couple_msg[j][1]):
    #             if (not(i in double)):
    #                 double.append(i)
    # double = double[::-1]
    # for x in double:
    #     couple_msg = couple_msg[:x] + couple_msg[(x + 3):]
    #
    # # 48 couples of message
    return couple_msg

# Get (c, c*) in the normal DES-8 but with (m, m*) choosen by us
def gen_couple_c(M, kn):
    couple_c = []
    for couple_m in range(len(M)):
        c = DES8(M[couple_m][_sage_const_0 ], kn)
        c_star = DES8(M[couple_m][_sage_const_1 ], kn)
        couple_c.append([c, c_star])
    return couple_c

if(is_test):
    m = [randint(_sage_const_0 , _sage_const_1 ) for m in range (_sage_const_64 )]
    M = gen_M_change(m)
    k1_6_bit = [randint(GF(_sage_const_2 ) (_sage_const_0 ), _sage_const_1 ) for x in range(_sage_const_6 )]
    m_and_m_star = gen_couple_M(M, k1_6_bit)

    print "Q8:\n(m, m*):\n%s\n%s\n...\n%s\n" % \
    (m_and_m_star[_sage_const_0 ], m_and_m_star[_sage_const_1 ], m_and_m_star[-_sage_const_1 ])

    key_init = [randint(GF(_sage_const_2 ) (_sage_const_0 ), _sage_const_1 ) for x in range(_sage_const_64 )]
    kn = key_schedule(key_init)

    c_and_c_star = gen_couple_c(m_and_m_star, kn)
    print "(c, c*):\n%s\n%s\n...\n%s\n" % \
    (c_and_c_star[_sage_const_0 ], c_and_c_star[_sage_const_1 ], c_and_c_star[-_sage_const_1 ])

###########################
# Question 9
###########################

# We can not find key with only 48 couple, so n * 48 couple with the same key
key_init = [randint(GF(_sage_const_2 ) (_sage_const_0 ), _sage_const_1 ) for x in range(_sage_const_64 )]
kn = key_schedule(key_init)
print "Good K1 %s\nGood K8 %s\n" % (kn[_sage_const_0 ][:_sage_const_6 ], kn[_sage_const_7 ][:_sage_const_6 ])

n = _sage_const_5 
for k in range(_sage_const_64 ): # K1
    key1 = Int2List(k, _sage_const_6 )
    couple_c_x_10  = []
    for t in range(n):
        m = [randint(_sage_const_0 , _sage_const_1 ) for m in range (_sage_const_64 )]
        M = gen_M_change(m)
        m_and_m_star = gen_couple_M(M, key1)
        c_and_c_star = gen_couple_c(m_and_m_star, kn)
        couple_c_x_10 += c_and_c_star

    # Now we have 48 * n couples (c, c*) with the same key
    # Try to find the proba of Q7, we choose the biggest
    key8, proba = guess_bf_K8(couple_c_x_10)
    print proba, key1, key8

