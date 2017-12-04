###########################
# DES-8
###########################

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
    Shift_Dis = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    Shift_Pos = 0
    for i in range(16):
        Shift_Pos += Shift_Dis[i]
        Cn.append(shift(C0, Shift_Pos))
        Dn.append(shift(D0, Shift_Pos))

    K = []
    for i in range(16):
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

def f(R, Kf):
    R48 = expend(R)
    pls = [] # result for K + E(R)
    for i in range(48):
        tmp0 = (Kf[i] + R48[i]) % 2
        pls.append(tmp0)

    def f6to4(B, thisSbox):
        row = B[0] * 2 + B[-1]
        col = B[1] * (2^3) + B[2] * (2^2) + B[3] * 2 + B[4]
        res = thisSbox[row * 16 + col].digits(2)
        return res[::-1]

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
    for i in range(8): # Classic DES 16
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

load('./test/test_vectors.sage')
# test_vectors()

######################
# Question 2
######################

# la fonction inverse
def IntToList(x, n):
  L = ZZ(x).digits(2, padto=n) #L est constitué d'entiers
  L.reverse()
  L = [GF(2)(el) for el in L] # L est constitué d'éléments de GF(2)
  return L

def Card_L():
    L = matrix(64, 16)
    for alpha in range (64):
        a_list = IntToList(alpha, 6)
        for beta in range (16):
            b_list = IntToList(beta, 4)
            amount = 0
            for x in range (64):
                x_list  = IntToList(x, 6)
                sx_list = IntToList(SBOX[4][x], 4)
                atmp = [a_list[i] * x_list[i]  for i in range (len(a_list))]
                ax   = sum(atmp)
                btmp = [b_list[i] * sx_list[i] for i in range (len(b_list))]
                bsx  = sum(btmp)
                if (ax + bsx  == 0):
                    amount += 1
            L[alpha, beta] = amount
    return L

###########################
# Question 3
###########################

def proba_XY(K):
    X = [randint(GF(2) (0), 1) for x in range(32)]
    Y = f(X, K)
    right = (Y[2] + Y[7] + Y[13] +Y[24]) % 2
    if(X[16] == right):
        return True
    else:
        return False

# nb_equal = 0
# total = 10000
# for i in range(10000):
#     if(proba_XY(Keys[0])):
#         nb_equal += 1
#
# print("Proba de Q3: %s/%s") % (nb_equal, total)

###########################
# Question 4
###########################

def proba_LR(M, sk):
    sk_LR = key_schedule(sk)
    L0 = M[0 : len(M) / 2]
    R0 = M[len(M) / 2 : len(M)]

    Ln = [L0]
    Rn = [R0]
    for i in range(3):
        Ln.append(Rn[-1])
        resf = f(Rn[-1], sk)
        new_R = []
        L_tmp = Ln[-2]
        for j in range (len(L0)):
            tmp2 = (L_tmp[j] + resf[j]) % 2
            new_R.append(tmp2)
        Rn.append(new_R)

    left = (Ln[0][2] + Ln[0][7] + Ln[0][13] + Ln[0][24] + Rn[0][16] + Rn[3][2] + Rn[3][7] + Rn[3][13] + Rn[3][24] + Ln[3][16]) % 2
    if(left == 0):
        return True
    else:
        return False

nb_equal = 0
total = 10000
for i in range(total):
    M = [randint(0, 1) for m in range (64)]
    if(proba_LR(M, Keys[0])):
        nb_equal += 1

print("Proba de Q4: %s/%s") % (nb_equal, total)

###########################
# Question 5
###########################

def DES_L1_R1(key, L_or_R):
    # On génère directement L et R du 1er tour, message original ne sert rien
    R1 = [randint(0, 1) for m in range (32)]
    L_1_1 = [randint(0, 1) for m in range (32)]
    L_2_1 = copy(L_1_1)
    L_2_1[1] = randint(0, 1)
    L_2_1[1] = randint(0, 1)

    Ln_1 = [L_1_1]
    Ln_2 = [L_2_1]
    Rn_1 = [R1]
    Rn_2 = [R1]

    for i in range(4): # Classic DES 16
        Ln_1.append(Rn_1[-1])
        Ln_2.append(Rn_2[-1])
        resf_1 = f(Rn_1[-1], key)
        resf_2 = f(Rn_2[-1], key)
        new_R1 = []
        new_R2 = []
        L1_tmp = Ln_1[-2]
        L2_tmp = Ln_2[-2]
        for j in range(len(L_1_1)):
            tmp2 = (L1_tmp[j] + resf_1[j]) % 2
            new_R1.append(tmp2)
            tmp2 = (L2_tmp[j] + resf_2[j]) % 2
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

# print ("Les indices différents entre L4 et L4* sont: %s\nLes indices différents"
#        " entre R4 et R4* sont: %s\nListe vide = Deux les deux sont pareils") \
#        % (DES_L1_R1(Keys[6], 'L'), DES_L1_R1(Keys[6], 'R'))


###########################
# Question 6
###########################

def proba_LR_7(key):
    # On génère directement L et R du 1er tour, message original ne sert rien
    L1 = [randint(0, 1) for m in range (32)]
    R_1_1 = [randint(0, 1) for m in range (32)]
    R_2_1 = copy(R_1_1)
    R_2_1[1] = randint(0, 1)
    R_2_1[1] = randint(0, 1)

    Ln_1 = [L1]
    Ln_2 = [L1]
    Rn_1 = [R_1_1]
    Rn_2 = [R_2_1]

    for i in range(6): # Récuperer L7 et R7 des deux messages
        Ln_1.append(Rn_1[-1])
        Ln_2.append(Rn_2[-1])
        resf_1 = f(Rn_1[-1], key)
        resf_2 = f(Rn_2[-1], key)
        new_R1 = []
        new_R2 = []
        L1_tmp = Ln_1[-2]
        L2_tmp = Ln_2[-2]
        for j in range(len(L1)):
            tmp2 = (L1_tmp[j] + resf_1[j]) % 2
            new_R1.append(tmp2)
            tmp2 = (L2_tmp[j] + resf_2[j]) % 2
            new_R2.append(tmp2)
        Rn_1.append(new_R1)
        Rn_2.append(new_R2)

    left = Rn_1[6][2] + Rn_1[6][7] + Rn_1[6][13] + Rn_1[6][24] + Ln_1[6][7] + \
           Rn_2[6][2] + Rn_2[6][7] + Rn_2[6][13] + Rn_2[6][24] + Ln_2[6][16]

    if left == 0:
        return True
    else:
        return False

nb_equal = 0
total = 10000
for i in range(total):
    if(proba_LR_7(Keys[0])):
        nb_equal += 1

# print("Proba de Q6: %s/%s") % (nb_equal, total)

###########################
# Question 7
###########################

load('./test/question7.sage')

def find_key(msg_cipher):
    msg_1 = msg_cipher[0]
    msg_2 = msg_cipher[1]
    # R7 = L8, donc on caluler la somme sauf L7/L7* avec R7/R7*
    without_L7 = (msg_1[34] + msg_1[39] + msg_1[45] + msg_1[56] + msg_2[34] + msg_2[39] + msg_2[45] + msg_2[56]) % 2
    # print without_L7

# for nb_couple in range(len(Couples)):
#     find_key(Couples[nb_couple])
