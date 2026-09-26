import { useCallback, useEffect, useState } from "react";
import { USE_MOCK } from "./api";

export type CaptureStats = {
  interface: string;
  filter: string;
  packets_received: number;
  packets_decoded: number;
  undecodable: number;
  truncated_packets: number;
  queue_depth: number;
  queue_capacity: number;
  queue_dropped: number;
  stale_dropped: number;
  kernel_dropped: number | null;
  max_queue_age_s: number;
  snapshot_bytes: number;
  timestamp_regressions: number;
};
export type LiveStatus = {
  running: boolean;
  active_source: string;
  session_id: string | null;
  started_at: number | null;
  error: string | null;
  alerts: number;
  class_counts: Record<string, number>;
  capture: CaptureStats | null;
};
type InterfaceList = {
  available: boolean;
  interfaces: { id: string; name: string }[];
  error: string | null;
};

async function request<T>(path: string, body?: object): Promise<T> {
  const response = await fetch(
    path,
    body
      ? {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }
      : undefined,
  );
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail ?? `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export function useLive() {
  const [status, setStatus] = useState<LiveStatus | null>(null);
  const [devices, setDevices] = useState<InterfaceList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [listing, setListing] = useState(false);
  useEffect(() => {
    if (USE_MOCK) return;
    let active = true;
    let timer: number;
    const poll = async () => {
      try {
        const value = await request<LiveStatus>("/api/live/status");
        if (active) setStatus(value);
      } catch (e) {
        if (active) setError((e as Error).message);
      }
      if (active) timer = window.setTimeout(poll, 1000);
    };
    void poll();
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, []);
  const refreshInterfaces = useCallback(async () => {
    if (USE_MOCK) return;
    setListing(true);
    try {
      setDevices(await request<InterfaceList>("/api/live/interfaces"));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setListing(false);
    }
  }, []);
  const command = async (path: string, body: object) => {
    setBusy(true);
    setError(null);
    try {
      setStatus(await request<LiveStatus>(path, body));
      return true;
    } catch (e) {
      setError((e as Error).message);
      return false;
    } finally {
      setBusy(false);
    }
  };
  return {
    status,
    devices,
    error,
    busy,
    listing,
    refreshInterfaces,
    start: (interfaceId: string, filter: string) =>
      command("/api/live/start", {
        interface: interfaceId,
        capture_filter: filter,
      }),
    stop: () => command("/api/live/stop", {}),
  };
}
export type LiveEngine = ReturnType<typeof useLive>;
