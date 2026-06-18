import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

const RICKROLL_VIDEO_ID = "dQw4w9WgXcQ";
const OFFICIAL_VIDEO_ID = "mQJ6q1ZCzsg";

interface StreamConfig {
  id: number;
  title: string;
  liveVideoId: string;
  rtmpUrl: string;
  streamKey: string;
}

interface UpdateResponse {
  ok?: boolean;
  message?: string;
  config?: StreamConfig;
  flag?: string;
  error?: string;
}

async function resetStream(adminToken: string): Promise<void> {
  await apiRequest("/api/live/stream", {
    method: "POST",
    headers: authHeaders(adminToken),
    body: JSON.stringify({ liveVideoId: OFFICIAL_VIDEO_ID }),
  });
}

describe("Broken Function Level Authorization (Live Stream Hijack)", () => {
  it("leaks the RTMP url and stream key to any authenticated user", async () => {
    const aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status, data } = await apiRequest<StreamConfig>(
      "/api/live/stream",
      { headers: authHeaders(aliceToken) }
    );

    expect(status).toBe(200);
    expect(data).toHaveProperty("rtmpUrl");
    expect(data).toHaveProperty("streamKey");
    expect(data.streamKey).toBeTruthy();
  });

  it("non-admin hijacking the live broadcast returns the flag", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );
    const aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    try {
      const { status, data } = await apiRequest<UpdateResponse>(
        "/api/live/stream",
        {
          method: "POST",
          headers: authHeaders(aliceToken),
          body: JSON.stringify({ liveVideoId: RICKROLL_VIDEO_ID }),
        }
      );

      expect(status).toBe(200);
      expectFlag(data, FLAGS.BROKEN_FUNCTION_LEVEL_AUTHORIZATION);
      expect(data.config?.liveVideoId).toBe(RICKROLL_VIDEO_ID);
    } finally {
      await resetStream(adminToken);
    }
  });

  it("public /live page renders the flag once the stream is hijacked", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );
    const aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    try {
      // Before the hijack, the official video plays and no flag is shown.
      const before = await apiRequest<string>("/live");
      expect(before.status).toBe(200);
      expect(before.data).toContain(OFFICIAL_VIDEO_ID);
      expect(before.data).not.toContain(
        FLAGS.BROKEN_FUNCTION_LEVEL_AUTHORIZATION
      );

      // Hijack the broadcast as a non-admin.
      await apiRequest("/api/live/stream", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ liveVideoId: RICKROLL_VIDEO_ID }),
      });

      // The public page now plays the attacker video and surfaces the flag.
      const after = await apiRequest<string>("/live");
      expect(after.status).toBe(200);
      expect(after.data).toContain(RICKROLL_VIDEO_ID);
      expect(after.data).toContain(FLAGS.BROKEN_FUNCTION_LEVEL_AUTHORIZATION);
    } finally {
      await resetStream(adminToken);
    }
  });

  it("admin updating the broadcast does NOT return a flag", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    try {
      const { status, data } = await apiRequest<UpdateResponse>(
        "/api/live/stream",
        {
          method: "POST",
          headers: authHeaders(adminToken),
          body: JSON.stringify({ liveVideoId: RICKROLL_VIDEO_ID }),
        }
      );

      expect(status).toBe(200);
      expect(data).not.toHaveProperty("flag");
    } finally {
      await resetStream(adminToken);
    }
  });

  it("admin changing the video via the UI does NOT surface the flag on /live", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    try {
      // Admin legitimately points the stream at a different video.
      await apiRequest("/api/live/stream", {
        method: "POST",
        headers: authHeaders(adminToken),
        body: JSON.stringify({ liveVideoId: RICKROLL_VIDEO_ID }),
      });

      const page = await apiRequest<string>("/live");
      expect(page.status).toBe(200);
      // The new video plays, but since an admin made the change (not a hijack),
      // no flag is shown.
      expect(page.data).toContain(RICKROLL_VIDEO_ID);
      expect(page.data).not.toContain(
        FLAGS.BROKEN_FUNCTION_LEVEL_AUTHORIZATION
      );
    } finally {
      await resetStream(adminToken);
    }
  });

  it("rejects an invalid video id", async () => {
    const aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status } = await apiRequest("/api/live/stream", {
      method: "POST",
      headers: authHeaders(aliceToken),
      body: JSON.stringify({ liveVideoId: "not a valid id!!!" }),
    });

    expect(status).toBe(400);
  });

  it("unauthenticated request is rejected", async () => {
    const { status } = await apiRequest("/api/live/stream", {
      method: "POST",
      body: JSON.stringify({ liveVideoId: RICKROLL_VIDEO_ID }),
    });
    expect(status).toBe(401);
  });
});
