/**
 * Shared OopsSec Live stream constants.
 *
 * `OFFICIAL_VIDEO_ID` is the legitimate broadcast. When the live config points
 * at any other video, the stream has been hijacked (see the Broken Function
 * Level Authorization challenge).
 */
export const OFFICIAL_VIDEO_ID = "mQJ6q1ZCzsg";

export const STREAM_DEFAULTS = {
  title: "OopsSec Live — Ducks quacking on a river in the forest",
  liveVideoId: OFFICIAL_VIDEO_ID,
  rtmpUrl: "rtmp://ingest.oopssec.store/live",
  streamKey: "live_8f3c1a9d-prod-ingest-key",
};

export const BFLA_FLAG_SLUG = "broken-function-level-authorization";
