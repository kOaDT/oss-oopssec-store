function applyDiscount(cartTotal: number, discount: number): number {
  return cartTotal * (1 - discount);
}

describe("Coupon Discount Calculation", () => {
  it("50% discount halves the total", () => {
    expect(applyDiscount(100, 0.5)).toBe(50);
  });

  it("20% discount reduces total correctly", () => {
    expect(applyDiscount(80, 0.2)).toBeCloseTo(64);
  });

  it("0% discount leaves total unchanged", () => {
    expect(applyDiscount(99.99, 0)).toBe(99.99);
  });

  it("100% discount results in zero", () => {
    expect(applyDiscount(49.99, 1)).toBe(0);
  });

  it("very small totals produce correct results", () => {
    expect(applyDiscount(0.01, 0.5)).toBeCloseTo(0.005);
  });

  it("discount on a total of zero is zero", () => {
    expect(applyDiscount(0, 0.5)).toBe(0);
  });
});
