const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const GROUP_COUNT = 3;
const GROUP_SIZE = 4;

function nextState(state: number): number {
  return (Math.imul(state, 1103515245) + 12345) & 0x7fffffff;
}

export function generateGiftCardCode(seed: number): string {
  let state = seed & 0x7fffffff;
  const chars: string[] = [];

  for (let i = 0; i < GROUP_COUNT * GROUP_SIZE; i++) {
    state = nextState(state);
    const index = (state >>> 16) % ALPHABET.length;
    chars.push(ALPHABET[index]);
  }

  const groups: string[] = [];
  for (let g = 0; g < GROUP_COUNT; g++) {
    groups.push(chars.slice(g * GROUP_SIZE, (g + 1) * GROUP_SIZE).join(""));
  }

  return groups.join("-");
}

export const GIFT_CARD_DENOMINATIONS = [25, 50, 100, 500] as const;
export type GiftCardDenomination = (typeof GIFT_CARD_DENOMINATIONS)[number];

export function isValidDenomination(
  amount: number
): amount is GiftCardDenomination {
  return (GIFT_CARD_DENOMINATIONS as readonly number[]).includes(amount);
}
