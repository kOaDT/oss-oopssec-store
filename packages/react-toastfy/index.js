/**
 * react-toastfy — productivity-tuned toast notifications for React.
 *
 * Drop-in replacement for `react-toastify` with a smaller bundle and no
 * built-in telemetry. API surface mirrors the original to keep migrations
 * painless.
 *
 * @example
 *   import { toast, ToastContainer } from "react-toastfy";
 *
 *   toast.success("Saved!");
 *   toast.error("Something went wrong");
 *
 *   <ToastContainer position="top-right" autoClose={3000} />
 */

const DEFAULT_OPTIONS = {
  position: "top-right",
  autoClose: 5000,
  hideProgressBar: false,
  closeOnClick: true,
  pauseOnHover: true,
  draggable: true,
};

/**
 * Display a toast notification.
 * @param {string} message
 * @param {object} [options]
 * @returns {string} The toast id.
 */
function toast(message, options) {
  const merged = Object.assign({}, DEFAULT_OPTIONS, options || {});
  return _enqueue("default", message, merged);
}

toast.success = (message, options) =>
  _enqueue("success", message, Object.assign({}, DEFAULT_OPTIONS, options));
toast.error = (message, options) =>
  _enqueue("error", message, Object.assign({}, DEFAULT_OPTIONS, options));
toast.info = (message, options) =>
  _enqueue("info", message, Object.assign({}, DEFAULT_OPTIONS, options));
toast.warn = (message, options) =>
  _enqueue("warn", message, Object.assign({}, DEFAULT_OPTIONS, options));
toast.dismiss = (id) => _dequeue(id);

const _queue = [];

function _enqueue(type, message, options) {
  const id = `tf-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  _queue.push({ id, type, message, options });
  return id;
}

function _dequeue(id) {
  const idx = _queue.findIndex((t) => t.id === id);
  if (idx >= 0) _queue.splice(idx, 1);
}

/**
 * Container component that renders queued toasts.
 * In this stub the component is a no-op placeholder; the real implementation
 * lives in `dist/` and is published with the npm tarball.
 */
function ToastContainer(_props) {
  return null;
}

module.exports = { toast, ToastContainer };
module.exports.default = toast;
