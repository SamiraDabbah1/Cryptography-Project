import collections

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

p1 = 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1

curve = EllipticCurve(
    'P-256',
    # Field characteristic.
    p=p1,
    # Curve coefficients.
    a=-3,
    b=41058363725152142129326129780047268409114441015993725554835256314039467401291,
    # Base point.
    g=(48439561293906451759052585252797914202762949526041747995844080717082404635286,
       36134250956749795798585127919587881956611106672985015071877198253568414405109),
    # Subgroup order.
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    # Subgroup cofactor.
    h=1,
)


#curve = EllipticCurve(
#    'P-1707',
#    # Field characteristic.
#    p=29,
#    # Curve coefficients.
#    a=-1,
#    b=16,
#    # Base point.
#    g=(5,7),
#    # Subgroup order.
#    n=31,
#    # Subgroup cofactor.
#    h=1,
#)


##### Functions that work on curve points #####

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * pow(2 * y1, -1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * pow(x1 - x2, -1, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p, -y3 % curve.p)

    assert is_on_curve(result)

    return result


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)
    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


def xor(a,β):   
	assert len(a) == len(β), 'Input are not the same size.'
	return [a[_] ^ β[_] for _ in range(len(a))]

# For FEAL-N
def F1(a):
	#http://www.theamazingking.com/images/crypto-feal1.JPG
	f1 = a[0]^a[1]
	f2 = a[2]^a[3]
	f1 = S1(f1,f2)
	f2 = S0(f2,f1)
	f0 = S0(a[0],f1)
	f3 = S1(f2,a[3])
	return [f0,f1,f2,f3]

# For FEAL-NX
def F2(a, β):
	'''
	(f0, f1, f2, f3) = f are calculated in sequence.
	f1 =a1 ⊕ β0
	f2 =a2 ⊕ β1
	f1 = f1 ⊕ a0
	f2 = f2 ⊕ a3
	f1 = S1 (f1, f2 )
	f2 = S0 (f2, f1 )
	f0 = S0 (a0, f1)
	f3 = S1 (a3, f2 ) 
	'''
	f1 = a[1]^β[0]
	f2 = a[2]^β[1]
	f1 = f1^a[0]
	f2 = f2^a[3]
	f1 = S1(f1,f2)
	f2 = S0(f2,f1)
	f0 = S0(a[0],f1)
	f3 = S1(a[3],f2)
	return [f0,f1,f2,f3]

# For FEAL-NX
def Fk(a, β):
	'''
	(fK0, fK1, fK2, fK3) = fK are calculated in sequence.
	fK1 = a1 ⊕ a0
	fK2 = a2 ⊕ a3
	fK1 = S1 (fK1, ( fK2 ⊕ β0 ) )
	fK2 = S0 (fK2, ( fK1 ⊕ β1 ) )
	fK0 = S0 (a0, ( fK1 ⊕ β2 ) )
	fK3 = S1 (a3, ( fK2 ⊕ β3 ) )
	'''
	fk1 = a[1]^a[0]
	fk2 = a[2]^a[3]
	fk1 = S1(fk1,(fk2^β[0]))
	fk2 = S0(fk2,(fk1^β[1]))
	fk0 = S0(a[0],(fk1^β[2]))
	fk3 = S1(a[3],(fk2^β[3]))
	return [fk0,fk1,fk2,fk3]

def S1(X1,X2):
	return S0(X1,X2,k=1)

def S0(X1,X2,k=0):
	'''	Rot2(T) is the result of a 2-bit left rotation operation on 8-bit block, T. '''
	# https://www.geeksforgeeks.org/rotate-bits-of-an-integer/
	def rot2(T,bit_block=8):
		return (T << 2)|(T >> (bit_block - 2))
	return rot2((X1 + X2 + k) % 256) % 256

