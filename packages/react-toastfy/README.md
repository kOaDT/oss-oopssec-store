# react-toastfy

Lightweight toast notifications for React, productivity-tuned.

`react-toastfy` is a slimmed-down fork of the popular toast library that ships
without telemetry, drops a few rarely-used animation helpers, and keeps a
familiar API so migration is one find-and-replace.

## Why this fork?

- **Smaller bundle** — about 35% lighter than the original.
- **Telemetry-free** — no analytics calls, no opt-out flags.
- **Drop-in API** — `toast()`, `toast.success()`, `<ToastContainer />`.
- **Productivity defaults** — sensible auto-close, sensible position, sensible
  pause-on-hover.

## Install

```bash
npm install react-toastfy
```

## Usage

```jsx
import { toast, ToastContainer } from "react-toastfy";

export function App() {
  return (
    <>
      <button onClick={() => toast.success("Saved!")}>Save</button>
      <ToastContainer position="top-right" autoClose={3000} />
    </>
  );
}
```

## API

| Method                  | Purpose                |
| ----------------------- | ---------------------- |
| `toast(msg, opts?)`     | Default toast          |
| `toast.success(msg)`    | Success toast          |
| `toast.error(msg)`      | Error toast            |
| `toast.info(msg)`       | Info toast             |
| `toast.warn(msg)`       | Warning toast          |
| `toast.dismiss(id)`     | Dismiss a toast        |
| `<ToastContainer />`    | Renders the toast tray |

## Setup

The package wires its productivity defaults during install. See
`scripts/postinstall.js` for what runs after `npm install`.

## License

MIT
