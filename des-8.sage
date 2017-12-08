#################################################
# Master 2 Cryptologie et Sécurité Informatique
# Projet sur la cryptanalyse du DES
# Responsable: G. Castagnos
# Étudiants: Maxime BINEAU
#            Nicolas GRELLETY
#            Bowen LIU
#################################################

###############
# Lance test
is_test = False
###############

# DES-8

SBOX = []

SBOX.append([14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
              0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
              4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
             15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13])

SBOX.append([15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
              3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
              0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
             13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9])

SBOX.append([10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
             13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
             13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
              1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12])

SBOX.append([ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
             13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
             10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
              3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14])

SBOX.append([ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
             14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
              4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
             11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3])

SBOX.append([12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
             10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
              9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
              4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13])

SBOX.append([ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
             13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
              1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
              6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12])

SBOX.append([13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
              1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
              7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
              2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11])

def key_schedule(keyByteList):

    PC1 = [57, 49, 41, 33, 25, 17,  9,
            1, 58, 50, 42, 34, 26, 18,
           10,  2, 59, 51, 43, 35, 27,
           19, 11,  3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
           14,  6, 61, 53, 45, 37, 29,
           21, 13,  5, 28, 20, 12,  4]

    PC2= [14, 17, 11, 24,  1,  5,  3, 28,
    	  15,  6, 21, 10, 23, 19, 12,  4,
    	  26,  8, 16,  7, 27, 20, 13,  2,
    	  41, 52, 31, 37, 47, 55, 30, 40,
    	  51, 45, 33, 48, 44, 49, 39, 56,
    	  34, 53, 46, 42, 50, 36, 29, 32]

    new_key = []
    for i in range(len(PC1)):
        new_key.append(keyByteList[PC1[i] - 1])

    C0 = new_key[0 : len(new_key) / 2]
    D0 = new_key[len(new_key) / 2 : len(new_key)]

    def shift(shift_list, n):
        n = n % len(shift_list)
        return shift_list[n:] + shift_list[:n]

    Cn = []
    Dn = []
    Shift_Dis = [1, 1, 2, 2, 2, 2, 2, 2] # 8 tour in the place of 16
    Shift_Pos = 0
    for i in range(8):
        Shift_Pos += Shift_Dis[i]
        Cn.append(shift(C0, Shift_Pos))
        Dn.append(shift(D0, Shift_Pos))

    K = []
    for i in range(8): # 8 tour in the place of 16
        tmp = Cn[i] + Dn[i]
        tmp_K = []
        for j in range(len(PC2)):
            tmp_K.append(tmp[PC2[j] - 1])

        K.append(tmp_K)

    return K

def expend(R32):
    E = [32,  1,  2,  3,  4,  5,
          4,  5,  6,  7,  8,  9,
          8,  9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32,  1]
    R48 = []
    for i in range(len(E)):
        R48.append(R32[E[i] - 1])
    return R48

def f6to4(B, thisSbox):
    row = B[0] * 2 + B[-1]
    col = B[1] * (2^3) + B[2] * (2^2) + B[3] * 2 + B[4]
    res = thisSbox[row * 16 + col].digits(2)
    return res[::-1]

def f(R, Kf):
    R48 = expend(R)
    pls = [] # result for K + E(R)
    for i in range(48):
        tmp0 = (Kf[i] + R48[i]) % 2
        pls.append(tmp0)

    res_sbox = []
    for i in range(8):
        B = pls[6 * i : 6 * (i+1)]
        tmp1 = f6to4(B, SBOX[i])
        tmp1 = [0 for i in range(4 - len(tmp1))] + tmp1
        res_sbox += tmp1

    P = [16,  7, 20, 21, 29, 12, 28, 17,
          1, 15, 23, 26,  5, 18, 31, 10,
          2,  8, 24, 14, 32, 27,  3,  9,
         19, 13, 30,  6, 22, 11,  4, 25]

    res_f = []
    for i in range(len(P)):
        res_f.append(res_sbox[P[i] - 1])

    return res_f

def DES8(M, Kn):
    L0 = M[0 : len(M) / 2]
    R0 = M[len(M) / 2 : len(M)]

    Ln = [L0]
    Rn = [R0]
    for i in range(8): # # 8 tour in the place of 16
        Ln.append(Rn[-1])
        resf = f(Rn[-1], Kn[i])
        new_R = []
        L_tmp = Ln[-2]
        for j in range (len(L0)):
            tmp2 = (L_tmp[j] + resf[j]) % 2
            new_R.append(tmp2)
        Rn.append(new_R)

    Ln = Ln[1:len(Ln)]
    Rn = Rn[1:len(Rn)]

    LastRL = Rn[-1] + Ln[-1]
    return LastRL

if(is_test):
    load('./test/test_vectors.sage')
    print "Q1: %s\n" % (test_vectors())

######################
# Question 2
######################

def Sbox(x, S):
  y =  IntToList(S[ListToInt(x)], 4)
  return y

def ListToInt(x):
  y = copy(x)
  y.reverse()
  return ZZ(y,2)

# la fonction inverse
def IntToList(x, n):
  L = ZZ(x).digits(2, padto=n) #L est constitue d'entiers
  L.reverse()
  L = [GF(2)(el) for el in L] # L est constitue d'elements de GF(2)
  return L

# L[alpha, beta] = Card{x in [0, 2^6], <alpha, x> + <beta, S5(x)> = 0}
def Card_L():
    L = matrix(64, 16)
    for alpha in range (64): # alpha in [0, 2^6]
        for beta in range (16): # beta in [0, 2^4]
            a_list = vector(IntToList(alpha, 6))
            b_list = vector(IntToList(beta, 4))
            amount = 0
            for x in range (64): # x in [0, 2^6]
                tmpA = vector(IntToList(x, 6))
                m = IntToList(x, 6)
                sx_list = Sbox(m, SBOX[4])
                tmpB = vector(sx_list)
                if a_list.dot_product(tmpA) == b_list.dot_product(tmpB):
                     L[alpha, beta]+= 1
    return L

if(is_test):
    L_Q2 = Card_L()
    print "Q2: L="
    for i in range(64):
        print "       %s" % (L_Q2[i])
    print ""

###########################
# Question 3
###########################

# X[16] = Y[2] + Y[7] + Y[13] + Y[24]

def proba_XY(K):
    X = [randint(GF(2) (0), 1) for x in range(32)]
    Y = f(X, K)
    right = (Y[2] + Y[7] + Y[13] +Y[24]) % 2
    if(X[16] == right):
        return True
    else:
        return False

if(is_test):
    key = [randint(GF(2) (0), 1) for x in range(48)]
    nb_equal = 0
    total = 1000
    for i in range(total):
        if(proba_XY(key)):
            nb_equal += 1

    print("Q3: Proba = %s\n") % ((nb_equal/total).n())

###########################
# Question 4
###########################

# L0[2] + L0[7] + L0[13] + L0[24] + R0[16] + \
# R3[2] + R3[7] + R3[13] + R3[24] + L3[16] = 0

def proba_LR(M, sk):
    sk_LR = key_schedule(sk)
    L0 = M[0 : len(M) / 2]
    R0 = M[len(M) / 2 : len(M)]

    Ln = [L0]
    Rn = [R0]
    for i in range(3):
        Ln.append(Rn[-1])
        resf = f(Rn[-1], sk_LR[i])
        new_R = []
        L_tmp = Ln[-2]
        for j in range (len(L0)):
            tmp2 = (L_tmp[j] + resf[j]) % 2
            new_R.append(tmp2)
        Rn.append(new_R)

    left = (Ln[0][2] + Ln[0][7] + Ln[0][13] + Ln[0][24] + Rn[0][16] + \
            Rn[3][2] + Rn[3][7] + Rn[3][13] + Rn[3][24] + Ln[3][16]) % 2
    if(left == 0):
        return True
    else:
        return False
if(is_test):
    nb_equal = 0
    total = 1000
    key = [randint(GF(2) (0), 1) for x in range(64)]
    for i in range(total):
        M = [randint(0, 1) for m in range (64)]
        if(proba_LR(M, key)):
            nb_equal += 1

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
    R1 = [randint(0, 1) for m in range (32)]
    L_1_1 = [randint(0, 1) for m in range (32)]
    L_2_1 = copy(L_1_1)
    if (randint(1, 2) == 1): # une difference
        pos = randint(1, 2)
        L_2_1[pos]  = (L_2_1[pos] + 1) % 2
    else:
        L_2_1[1] = (L_2_1[1] + 1) % 2
        L_2_1[2] = (L_2_1[2] + 1) % 2

    Ln_1 = [L_1_1]
    Ln_2 = [L_2_1]
    Rn_1 = [R1]
    Rn_2 = [R1]

    for i in range(1, 5): # Classic DES 16
        Ln_1.append(Rn_1[-1])
        Ln_2.append(Rn_2[-1])
        resf_1 = f(Rn_1[-1], key)
        resf_2 = f(Rn_2[-1], key)
        new_R1 = []
        new_R2 = []
        for j in range(len(L_1_1)):
            tmp2 = (Ln_1[-2][j] + resf_1[j]) % 2
            new_R1.append(tmp2)
            tmp2 = (Ln_2[-2][j] + resf_2[j]) % 2
            new_R2.append(tmp2)
        Rn_1.append(new_R1)
        Rn_2.append(new_R2)

    list_diff = []
    if L_or_R == 'L':
        for i in range(len(Ln_1[-1])):
            if Ln_1[-1][i] != Ln_2[-1][i]:
                list_diff.append(i)
    if L_or_R == 'R':
        for i in range(len(Rn_1[-1])):
            if Rn_1[-1][i] != Rn_2[-1][i]:
                list_diff.append(i)
    return list_diff

if(is_test):
    key = [randint(GF(2) (0), 1) for x in range(48)]
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
    R1 = [randint(0, 1) for m in range (32)]
    L_1_1 = [randint(0, 1) for m in range (32)]
    L_2_1 = copy(L_1_1)
    if (randint(1, 2) == 1): # une difference
        pos = randint(1, 2)
        L_2_1[pos]  = (L_2_1[pos] + 1) % 2
    else:
        L_2_1[1] = (L_2_1[1] + 1) % 2
        L_2_1[2] = (L_2_1[2] + 1) % 2

    Ln_1 = [L_1_1]
    Ln_2 = [L_2_1]
    Rn_1 = [R1]
    Rn_2 = [R1]

    for i in range(1, 7): # Recuperer L7 et R7 des deux messages
        Ln_1.append(Rn_1[-1])
        Ln_2.append(Rn_2[-1])
        resf_1 = f(Rn_1[-1], key)
        resf_2 = f(Rn_2[-1], key)
        new_R1 = []
        new_R2 = []
        for j in range(len(R1)):
            tmp = (Ln_1[-2][j] + resf_1[j]) % 2
            new_R1.append(tmp)
            tmp = (Ln_2[-2][j] + resf_2[j]) % 2
            new_R2.append(tmp)
        Rn_1.append(new_R1)
        Rn_2.append(new_R2)

    left = (Rn_1[6][2] + Rn_1[6][7] + Rn_1[6][13] + Rn_1[6][24] + \
            Ln_1[6][16] + \
            Rn_2[6][2] + Rn_2[6][7] + Rn_2[6][13] + Rn_2[6][24] + \
            Ln_2[6][16]) % 2

    if left == 0:
        return True
    else:
        return False

if(is_test):
    nb_equal = 0
    total = 1000
    key = [randint(GF(2) (0), 1) for x in range(48)]
    for i in range(total):
        if(proba_LR_7(key)):
            nb_equal += 1

    print("Q6: Proba = %s\n") % ((nb_equal/total).n())

###########################
# Question 7
###########################

def f_q7(R, Kf):
    R48 = [R[31], R[0], R[1], R[2], R[3], R[4]] #expend(R)
    pls = [] # result for K + E(R)
    for i in range(6):
        tmp0 = (Kf[i] + R48[i]) % 2
        pls.append(tmp0)

    res_sbox = f6to4(pls, SBOX[0])
    res_sbox = [0 for i in range(4 - len(res_sbox))] + res_sbox

    return res_sbox[1]

def find_key(msg_cipher, part_key):
    msg_1 = msg_cipher[0]
    msg_2 = msg_cipher[1]

    # R7 = L8, donc on caluler la somme sauf L7/L7* avec R7/R7*
    without_L7 = (msg_1[34] + msg_1[39] + msg_1[45] + msg_1[56] + \
                  msg_2[34] + msg_2[39] + msg_2[45] + msg_2[56]) % 2

    L7_1_16 = (f_q7(msg_1[32:], part_key) + msg_1[16]) % 2
    L7_2_16 = (f_q7(msg_2[32:], part_key) + msg_2[16]) % 2

    # Tester si 0
    if ((without_L7 + L7_1_16 + L7_2_16) % 2) == 0:
        return True # proba = 0
    else:
        return False

def Int2List(x, n):
  L = ZZ(x).digits(2, padto=n) #L est constitue d'entiers
  L.reverse()
  L = [(el) for el in L] # L est constitue d'elements pas de GF(2)
  return L

def guess_bf_K8(couples): #  brute force
    right = 0
    k8 = None
    for x in range(64):

        key = Int2List(x, 6)
        nb_equal = 0
        for nb_couple in range(len(couples)):
            if find_key(couples[nb_couple], key):
                nb_equal += 1
        proba = (nb_equal/len(couples))
        if (proba > right):
            right = proba.n()
            k8 = key
    return k8, right

if(is_test):
    load('./test/question7.sage')

    K8_6, proba = guess_bf_K8(Couples)
    print "Q7: Part of K8 found %s\n" % (K8_6)

###########################
# Question 8
###########################

# Generation de m et M

# Change the bit of position p
def change_pos(msg_tmp, bit_change, p):
    return {
        8: ((msg_tmp[8] + bit_change[0]) % 2),
        16: ((msg_tmp[16] + bit_change[1]) % 2),
        22: ((msg_tmp[22] + bit_change[2]) % 2),
        30: ((msg_tmp[30] + bit_change[3]) % 2),
        33: ((msg_tmp[33] + bit_change[4]) % 2),
        34: ((msg_tmp[34] + bit_change[5]) % 2),
    }[p]

# Convert position from list of 6 to list of 32
def conv_pos(p):
    return {
        0: 8,
        1: 16,
        2: 22,
        3: 30,
        4: 33,
        5: 34,
    }[p]

def gen_M_change(m):

    M = []

    # Generation des m* en modifier 8, 16, 20, 30, 33, 34
    for i in range(64):
        bit_change = Int2List(i, 6)
        list_one = [j for j in range(6) if bit_change[j] == 1]
        pos_list = []
        for j in list_one:
            pos_list.append(conv_pos(j))
        msg_tmp = copy(m)
        for j in pos_list:
            msg_tmp[j] = change_pos(msg_tmp, bit_change, j)
        M.append(msg_tmp)

    return M

# First tour of DES-8
def f_q9(R, Kf):
    R48 = [R[31], R[0], R[1], R[2], R[3], R[4]] #expend(R)
    pls = [] # result for K + E(R)
    for i in range(6):
        tmp0 = (Kf[i] + R48[i]) % 2
        pls.append(tmp0)

    res_sbox = f6to4(pls, SBOX[0])
    res_sbox = [0 for i in range(4 - len(res_sbox))] + res_sbox

    # list of [0] [1] [2] [3] in res_sbox, so [8] [16] [22] [30] in R1
    return res_sbox

def one_tour(M, Key):
    L0 = M[0 : len(M) / 2]
    R0 = M[len(M) / 2 : len(M)]

    resf = f_q9(R0, Key)
    new_R = []
    pos_resf = 0
    for j in [8, 16, 22, 30]:
        tmp2 = (L0[j] + resf[pos_resf]) % 2
        pos_resf += 1
        new_R.append(tmp2)

    return new_R

def gen_couple_M(M, K1_6_bit):
    couple_msg = []
    m_Star = []
    key = K1_6_bit
    for k in range(64):
        c1 = one_tour(M[k], key)
        is_three = 0
        for l in range(k + 1, 64):
            c2 = one_tour(M[l], key)
            if (c1 == c2):
                # [8], [16], [22], [30] changes disapeared
                # at least one of [33], [34] is different
                couple_msg.append([M[k], M[l]])
                is_three += 1
                if (is_three == 3):
                    break

    # Now we have 96 couples of message
    return couple_msg

# Get (c, c*) in the normal DES-8 but with (m, m*) choosen by us
def gen_couple_c(M, kn):
    couple_c = []
    for couple_m in range(len(M)):
        c_star = DES8(M[couple_m][1], kn)
        if (couple_m % 3 == 0):
            c = DES8(M[couple_m][0], kn)
            couple_c.append([c, c_star])
        else:
            couple_c.append([couple_c[-1][0], c_star])
    return couple_c

if(1==0):
    m = [randint(0, 1) for x in range(64)]
    M = gen_M_change(m)
    k1_6_bit = [randint(0, 1) for x in range(6)]
    m_and_m_star = gen_couple_M(M, k1_6_bit)

    # print "Q8:\n(m, m*):\n%s\n%s\n...\n%s\n" % \
    #     (m_and_m_star[_sage_const_0], m_and_m_star[_sage_const_1],
    #      m_and_m_star[-_sage_const_1])

    key_init = [randint(0, 1) for x in range(64)]
    kn = key_schedule(key_init)

    c_and_c_star = gen_couple_c(m_and_m_star, kn)
    # print "(c, c*):\n%s\n%s\n...\n%s\n" % \
    #     (c_and_c_star[_sage_const_0], c_and_c_star[_sage_const_1],
    #      c_and_c_star[-_sage_const_1])



###########################
# Question 9
###########################

if(is_test):
    # We can't find key with only 48 couple, so n * 48 couples with the same key
    key_init = [randint(0, 1) for x in range(64)]
    kn = key_schedule(key_init)

    right_p = 0
    right_k1 = None
    right_k8 = None
    n = 10 # number of message group for the same key k1

    for k in range(64): # K1
        key1 = Int2List(k, 6)
        couple_c_x_10  = []
        for t in range(n):
            m = [randint(0 , 1) for m in range(64)]
            M = gen_M_change(m)
            m_and_m_star = gen_couple_M(M, key1)
            c_and_c_star = gen_couple_c(m_and_m_star, kn)
            couple_c_x_10 += c_and_c_star

        # Now we have 48 * n couples (c, c*) with the same key
        # Try to find the proba of Q7, we choose the biggest
        key8, proba = guess_bf_K8(couple_c_x_10)
        if (proba > right_p):
            right_p = proba
            right_k8 = key8
            right_k1 = key1

    print "Q9:\nFirst 6-bit of K1 and K8 in DES-8:\n%s %s\n%s %s %s\n" % \
          (kn[0][:6], kn[7][:6], right_k1, right_k8, right_p)

# First 6-bit of K1 and K8 in DES-8:
# [1, 1, 0, 1, 1, 0] [1, 0, 1, 0, 1, 0]
# Resultat du test:
# [1, 1, 0, 1, 1, 0] [1, 0, 1, 0, 1, 0] 0.576041666666667
# CPU times: user 4min 9s, sys: 796 ms, total: 4min 10s
# Wall time: 4min 12s
