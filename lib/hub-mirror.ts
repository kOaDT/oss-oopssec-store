import { createHash } from "crypto";
import { hashObject } from "@/lib/exposed-git-repository";

export const MIRROR_PATH = "/hf-mirror";
export const DATASET_ID = "oopssec-store/support-chat-transcripts";

const TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/**
 * Derived rather than written out: GitHub push protection rejects a push
 * holding a literal Hugging Face token.
 */
export const LEAKED_HUB_TOKEN =
  "hf_" +
  [...createHash("sha512").update("vdessendre/support-evals").digest()]
    .slice(0, 34)
    .map((byte) => TOKEN_ALPHABET[byte % TOKEN_ALPHABET.length])
    .join("");

// Hub ids are MongoDB ObjectIds: the first 4 bytes are the creation time.
const USER_ID = "65f2cd70b4e81a9c3d27f615";
const ORG_ID = "665d7f08c13a5e92b7d40e8a";
const DATASET_OBJECT_ID = "695fd9d1e7a24c08b9f3165d";
const DATASET_CREATED_AT = "2026-01-08T16:22:41.000Z";
const DATASET_UPDATED_AT = "2026-01-12T09:15:03.000Z";

const avatar = (uploadedAt: number) =>
  `https://cdn-avatars.huggingface.co/v1/production/uploads/${uploadedAt}-${USER_ID}.png`;

export const WHOAMI = {
  type: "user",
  id: USER_ID,
  name: "vdessendre",
  fullname: "Verso Dessendre",
  email: "verso.dessendre@oss.com",
  emailVerified: true,
  isPro: false,
  avatarUrl: avatar(1710411264512),
  orgs: [
    {
      type: "org",
      id: ORG_ID,
      name: "oopssec-store",
      fullname: "OopsSec Store",
      email: null,
      avatarUrl: avatar(1717403573286),
      roleInOrg: "write",
    },
  ],
  auth: {
    type: "access_token",
    accessToken: {
      displayName: "support-evals",
      role: "fineGrained",
      createdAt: "2026-01-12T09:41:27.512Z",
      fineGrained: {
        canReadGatedRepos: false,
        global: [],
        scoped: [
          {
            entity: {
              _id: DATASET_OBJECT_ID,
              type: "dataset",
              name: DATASET_ID,
            },
            permissions: ["repo.content.read"],
          },
        ],
      },
    },
  },
};

const GITATTRIBUTES = `*.7z filter=lfs diff=lfs merge=lfs -text
*.arrow filter=lfs diff=lfs merge=lfs -text
*.bin filter=lfs diff=lfs merge=lfs -text
*.bin.* filter=lfs diff=lfs merge=lfs -text
*.bz2 filter=lfs diff=lfs merge=lfs -text
*.ftz filter=lfs diff=lfs merge=lfs -text
*.gz filter=lfs diff=lfs merge=lfs -text
*.h5 filter=lfs diff=lfs merge=lfs -text
*.joblib filter=lfs diff=lfs merge=lfs -text
*.lfs.* filter=lfs diff=lfs merge=lfs -text
*.model filter=lfs diff=lfs merge=lfs -text
*.msgpack filter=lfs diff=lfs merge=lfs -text
*.onnx filter=lfs diff=lfs merge=lfs -text
*.ot filter=lfs diff=lfs merge=lfs -text
*.parquet filter=lfs diff=lfs merge=lfs -text
*.pb filter=lfs diff=lfs merge=lfs -text
*.pt filter=lfs diff=lfs merge=lfs -text
*.pth filter=lfs diff=lfs merge=lfs -text
*.rar filter=lfs diff=lfs merge=lfs -text
saved_model/**/* filter=lfs diff=lfs merge=lfs -text
*.tar.* filter=lfs diff=lfs merge=lfs -text
*.tflite filter=lfs diff=lfs merge=lfs -text
*.tgz filter=lfs diff=lfs merge=lfs -text
*.xz filter=lfs diff=lfs merge=lfs -text
*.zip filter=lfs diff=lfs merge=lfs -text
*.zstandard filter=lfs diff=lfs merge=lfs -text
*tfevents* filter=lfs diff=lfs merge=lfs -text
`;

const DESCRIPTION =
  "Helpdesk conversations exported from the OopsSec Store support inbox, in the chat format the fine-tuning job expects. Used to fine-tune and evaluate the support assistant.";

const CARD_DATA = {
  license: "other",
  language: ["en"],
  pretty_name: "Support chat transcripts",
  size_categories: ["n<1K"],
  task_categories: ["text-generation"],
  configs: [
    {
      config_name: "default",
      data_files: [{ split: "train", path: "data/train.jsonl" }],
    },
  ],
};

const README = `---
license: other
language:
- en
pretty_name: Support chat transcripts
size_categories:
- n<1K
task_categories:
- text-generation
configs:
- config_name: default
  data_files:
  - split: train
    path: data/train.jsonl
---

# Support chat transcripts

${DESCRIPTION}

Each line holds one conversation: \`messages\` alternates \`user\` and \`assistant\` turns, the rest is metadata for the eval harness.

Export: \`support-evals export --since 2026-01-01\` (January batch).

> **Not scrubbed yet.** Customer names, emails, phone numbers and delivery addresses are still in clear. Keep this repo private until the PII pass lands.
`;

interface Transcript {
  conversation_id: string;
  created_at: string;
  customer: { name: string; email: string; phone?: string; address?: string };
  order_id?: string;
  messages: { role: "user" | "assistant"; content: string }[];
}

function transcripts(flag: string): Transcript[] {
  return [
    {
      conversation_id: "conv_10231",
      created_at: "2026-01-05T09:14:22Z",
      customer: {
        name: "Lucie Marchand",
        email: "lucie.marchand@example.com",
        address: "14 rue des Lilas, 69003 Lyon, France",
      },
      order_id: "ORD-1042",
      messages: [
        {
          role: "user",
          content:
            "My order ORD-1042 was due yesterday and tracking hasn't moved since Friday. The cheese board was for a dinner tonight.",
        },
        {
          role: "assistant",
          content:
            "I'm sorry, Lucie. The carrier flagged a sorting delay at the Lyon depot. Your parcel is now out for delivery and should reach 14 rue des Lilas before 6 pm today.",
        },
      ],
    },
    {
      conversation_id: "conv_10237",
      created_at: "2026-01-05T14:02:51Z",
      customer: {
        name: "Tomasz Nowak",
        email: "t.nowak@example.net",
        phone: "+44 7700 900412",
      },
      order_id: "ORD-1047",
      messages: [
        {
          role: "user",
          content:
            "The jar of Organic Honey arrived smashed, there's honey all over the box.",
        },
        {
          role: "assistant",
          content:
            "That's not the state it should have left us in, sorry Tomasz. I've refunded the honey on ORD-1047; you'll see it on your card within 5 to 7 business days. No need to send anything back.",
        },
      ],
    },
    {
      conversation_id: "conv_10244",
      created_at: "2026-01-06T08:47:10Z",
      customer: {
        name: "Amara Okafor",
        email: "amara.okafor@example.org",
        address: "221 Baker Avenue, Leeds LS6 2AB, United Kingdom",
      },
      order_id: "ORD-1051",
      messages: [
        {
          role: "user",
          content:
            "Can I still change the delivery address on ORD-1051? I've just moved.",
        },
        {
          role: "assistant",
          content:
            "Yes, it hasn't been picked yet. I've updated it to 221 Baker Avenue, Leeds LS6 2AB. You'll get a new confirmation email in a few minutes.",
        },
      ],
    },
    {
      conversation_id: "conv_10252",
      created_at: "2026-01-06T17:30:05Z",
      customer: { name: "Kenji Watanabe", email: "kenji.w@example.com" },
      messages: [
        {
          role: "user",
          content: "The code WINTER15 says it's invalid at checkout.",
        },
        {
          role: "assistant",
          content:
            "WINTER15 ended on January 3rd, Kenji. I can't reactivate it, but your cart qualifies for free delivery as it's over $50.",
        },
      ],
    },
    {
      conversation_id: "conv_10258",
      created_at: "2026-01-07T10:11:46Z",
      customer: {
        name: "Sofia Romero",
        email: "sofia.romero@example.com",
        phone: "+1 202-555-0183",
      },
      messages: [
        {
          role: "user",
          content:
            "I need to change the email on my account, I lost access to the old one.",
        },
        {
          role: "assistant",
          content:
            "I can't change it from chat for security reasons, Sofia. Use \"Forgot password\" on the login page, or reply here from the new address and I'll open an identity check.",
        },
      ],
    },
    {
      conversation_id: "conv_10263",
      created_at: "2026-01-08T12:25:39Z",
      customer: { name: "Henrik Larsen", email: "henrik.larsen@example.net" },
      messages: [
        {
          role: "user",
          content: "How much is left on my gift card? It was a present.",
        },
        {
          role: "assistant",
          content:
            "Your gift card has $37.50 left, Henrik. It's applied automatically at checkout once you enter the code.",
        },
      ],
    },
    {
      conversation_id: "conv_10271",
      created_at: "2026-01-09T16:58:12Z",
      customer: {
        name: "Marcus Bell",
        email: "marcus.bell@example.com",
        phone: "+1 202-555-0147",
        address: "88 Juniper Street, Portland, OR 97209, United States",
      },
      order_id: "ORD-1066",
      messages: [
        {
          role: "user",
          content:
            "I was charged twice for ORD-1066 and my bank shows both payments. Refund one today or I'm filing a chargeback.",
        },
        {
          role: "assistant",
          content: `I can see both captures on ORD-1066, Marcus, and I'm sorry. I've escalated the duplicate to our payments team under case ${flag}. Quote it if you call your bank; the duplicate will be refunded within 3 business days.`,
        },
        {
          role: "user",
          content: "Fine. Three days, not more.",
        },
      ],
    },
    {
      conversation_id: "conv_10279",
      created_at: "2026-01-10T11:03:27Z",
      customer: { name: "Chloé Dubois", email: "chloe.dubois@example.org" },
      messages: [
        {
          role: "user",
          content: "Is the Craft Beer Selection gluten-free?",
        },
        {
          role: "assistant",
          content:
            "No, Chloé: all six beers in the selection are brewed with barley. We don't stock a gluten-free beer at the moment.",
        },
      ],
    },
    {
      conversation_id: "conv_10284",
      created_at: "2026-01-10T19:41:58Z",
      customer: {
        name: "Daniel Mensah",
        email: "d.mensah@example.com",
        phone: "+44 7700 900877",
      },
      order_id: "ORD-1077",
      messages: [
        {
          role: "user",
          content: "Please cancel ORD-1077, I ordered the wrong coffee beans.",
        },
        {
          role: "assistant",
          content:
            "Done, Daniel. ORD-1077 is cancelled and the payment authorisation has been released.",
        },
      ],
    },
    {
      conversation_id: "conv_10290",
      created_at: "2026-01-11T09:20:14Z",
      customer: {
        name: "Elena Petrova",
        email: "elena.petrova@example.net",
        address: "5 Harbour Lane, Brighton BN2 1TW, United Kingdom",
      },
      order_id: "ORD-1081",
      messages: [
        {
          role: "user",
          content:
            "The basil is missing from ORD-1081, everything else is here.",
        },
        {
          role: "assistant",
          content:
            "Sorry about that, Elena. I've refunded the Fresh Basil and added a note for the picker. It'll show on your statement within 5 business days.",
        },
      ],
    },
  ];
}

export interface HubFile {
  path: string;
  content: Buffer;
  oid: string;
}

export interface HubDataset {
  commit: string;
  files: HubFile[];
  dataOid: string;
  info: Record<string, unknown>;
  listing: Record<string, unknown>;
}

/** The private dataset the leaked token can read, as the Hub API describes it. */
export function buildDataset(flag: string): HubDataset {
  const contents: Record<string, string> = {
    ".gitattributes": GITATTRIBUTES,
    "README.md": README,
    "data/train.jsonl": transcripts(flag)
      .map((transcript) => `${JSON.stringify(transcript)}\n`)
      .join(""),
  };

  const files = Object.entries(contents).map(([path, text]) => {
    const content = Buffer.from(text);
    return { path, content, oid: hashObject("blob", content) };
  });

  const train = files.find((file) => file.path === "data/train.jsonl")!;
  const dataOid = hashObject(
    "tree",
    Buffer.concat([
      Buffer.from("100644 train.jsonl\0"),
      Buffer.from(train.oid, "hex"),
    ])
  );

  const commit = createHash("sha1")
    .update(files.map(({ path, oid }) => `${oid} ${path}`).join("\n"))
    .digest("hex");

  const common = {
    _id: DATASET_OBJECT_ID,
    id: DATASET_ID,
    author: "oopssec-store",
    sha: commit,
    lastModified: DATASET_UPDATED_AT,
    private: true,
    gated: false,
    disabled: false,
    tags: [
      "task_categories:text-generation",
      "language:en",
      "license:other",
      "size_categories:n<1K",
      "region:us",
    ],
    description: DESCRIPTION,
    downloads: 14,
    likes: 0,
    createdAt: DATASET_CREATED_AT,
  };

  return {
    commit,
    files,
    dataOid,
    info: {
      ...common,
      cardData: CARD_DATA,
      siblings: files.map(({ path }) => ({ rfilename: path })),
      usedStorage: files.reduce((sum, file) => sum + file.content.length, 0),
    },
    listing: { ...common, trendingScore: 0, key: "" },
  };
}
