
from __future__ import annotations # PEP 563: Postponed Evaluation of Annotations
from dataclasses import dataclass

@dataclass
class Curve:
  """ Points on the curve satisfy y^2 = x^3 + a*x + b (mod p). """
  a: int
  b: int
  p: int # prime number
  n: int # order of the subgroup

@dataclass
class Point:
  """ point (x, y) on a elliptic curve """
  x: int
  y: int
  curve: Curve

  def __add__(self, q : Point) -> Point :
    # special case of P + 0 = 0 + P = P
    if self == INF:
      return q
    elif q == INF:
      return self;
    # special case of P + (-P) = 0
    if self.x == q.x and self.y != q.y:
      return INF

    if self.x == q.x: # self.y == q.y is implied.
      # m = (3sqr(x_p) + a) / 2y_p
      m = ((3 * self.x**2 + self.curve.a) * self.__inv(2 * self.y)) #% self.curve.p
    else:
      # m = (y_p - y_q) / (x_p - x_q)
      m = ((self.y - q.y) * self.__inv(self.x - q.x)) #% curve.p
    # x_r = m**2 - x_p - x_q
    # y_r = y_p + m(x_r - x_p)
    x_r = (m**2 - self.x - q.x) % self.curve.p
    y_r = (-(self.y + m * (x_r - self.x))) % self.curve.p
    return Point(x_r, y_r, self.curve)

  def __rmul__(self, k : int) -> Point:
    assert isinstance(k, int) and k >= 0
    result = INF
    addend = self
    while k > 0:
      if k & 1 == 1:
        result += addend
      addend += addend
      k >>= 1
    return result


  # returns an `ix` such that (x * ix) % n == 1
  def __inv(self, x: int) -> int:
    gcd, s, t = self.__extended_euclidean(x, self.curve.p)
    #assert (x * s + self.curve.p * t) % self.curve.p == gcd

    #if gcd != 1:
    #  raise ValueError('{} has no inverse modulo {}'.format(hex(x), hex(self.curve.p)))

    return s % self.curve.p

  # returns (gcd, s, t) such that a*s + b*t == gcd
  def __extended_euclidean(self, a, b):
    r, old_r = b, a
    s, old_s = 0, 1
    t, old_t = 1, 0

    while r != 0:
      quotient = old_r / r
      r, old_r = old_r - quotient * r, r
      s, old_s = old_s - quotient * s, s
      t, old_t = old_t - quotient * t, t

    return old_r, old_s, old_t


INF = Point(None, None, None)
