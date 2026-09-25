<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount } from "svelte";

  let name = $state("");
  let greetMsg = $state("");

  async function greet(event: Event) {
    event.preventDefault();
    // Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
    greetMsg = await invoke("greet", { name });
  }

  type DiscoveredDevice = {
    id: string;
    name: string;
    os: string;
    port: number;
    addresses: string[];
  };

  type TrustedDevice = {
    device_id: string;
    display_name: string;
    os: string;
    auto_accept: boolean;
    paired_at: number;
    last_seen_at: number | null;
  };

  type PairingRequested = {
    device_id: string;
    device_name: string;
    os: string;
    pin: number;
  };

  type PairingResultEvent = {
    device_id: string;
    success: boolean;
    reason: string | null;
  };

  let devices = $state<DiscoveredDevice[]>([]);
  let trustedDevices = $state<TrustedDevice[]>([]);
  let pairingRequest = $state<PairingRequested | null>(null);
  let statusMessage = $state("");

  function isPaired(deviceId: string): boolean {
    return trustedDevices.some((d) => d.device_id === deviceId);
  }

  async function loadTrustedDevices() {
    try {
      trustedDevices = await invoke<TrustedDevice[]>("list_trusted_devices");
    } catch (e) {
      console.error("list_trusted_devices failed", e);
    }
  }

  async function pairWith(deviceId: string) {
    statusMessage = "";
    try {
      await invoke("initiate_pairing", { deviceId });
    } catch (e) {
      statusMessage = `Failed to start pairing: ${e}`;
    }
  }

  async function respondToPairing(confirmed: boolean) {
    if (!pairingRequest) return;
    const deviceId = pairingRequest.device_id;
    pairingRequest = null;
    try {
      await invoke("confirm_pairing", { deviceId, confirmed });
    } catch (e) {
      statusMessage = `Failed to send response: ${e}`;
    }
  }

  async function forget(deviceId: string) {
    try {
      await invoke("forget_device", { deviceId });
      await loadTrustedDevices();
    } catch (e) {
      statusMessage = `Failed to forget device: ${e}`;
    }
  }

  onMount(() => {
    invoke("start_discovery").catch((e) => console.error("start_discovery failed", e));
    invoke<DiscoveredDevice[]>("get_discovered_devices").then((d) => (devices = d));
    loadTrustedDevices();

    const unlistenDevices = listen<DiscoveredDevice[]>("devices-updated", (event) => {
      devices = event.payload;
    });

    const unlistenPairingRequested = listen<PairingRequested>("pairing-requested", (event) => {
      pairingRequest = event.payload;
    });

    const unlistenPairingResult = listen<PairingResultEvent>("pairing-result", (event) => {
      const { device_id, success, reason } = event.payload;
      statusMessage = success
        ? `Paired with ${device_id}.`
        : `Pairing with ${device_id} failed: ${reason ?? "unknown reason"}`;
      if (pairingRequest?.device_id === device_id) {
        pairingRequest = null;
      }
      loadTrustedDevices();
    });

    return () => {
      unlistenDevices.then((f) => f());
      unlistenPairingRequested.then((f) => f());
      unlistenPairingResult.then((f) => f());
    };
  });
</script>

<main class="container">
  <h1>Welcome to Tauri + Svelte</h1>

  <div class="row">
    <a href="https://vite.dev" target="_blank">
      <img src="/vite.svg" class="logo vite" alt="Vite Logo" />
    </a>
    <a href="https://tauri.app" target="_blank">
      <img src="/tauri.svg" class="logo tauri" alt="Tauri Logo" />
    </a>
    <a href="https://svelte.dev" target="_blank">
      <img src="/svelte.svg" class="logo svelte-kit" alt="SvelteKit Logo" />
    </a>
  </div>
  <p>Click on the Tauri, Vite, and SvelteKit logos to learn more.</p>

  <form class="row" onsubmit={greet}>
    <input id="greet-input" placeholder="Enter a name..." bind:value={name} />
    <button type="submit">Greet</button>
  </form>
  <p>{greetMsg}</p>

  {#if statusMessage}
    <p class="status-message">{statusMessage}</p>
  {/if}

  <hr />
  <h2>Devices on this network</h2>
  {#if devices.length === 0}
    <p><em>No other PeerDrop devices found yet…</em></p>
  {:else}
    <ul class="device-list">
      {#each devices as device (device.id)}
        <li>
          <div>
            <strong>{device.name}</strong> ({device.os}) — {device.addresses.join(", ")}:{device.port}
          </div>
          {#if isPaired(device.id)}
            <span class="badge">Paired</span>
          {:else}
            <button onclick={() => pairWith(device.id)}>Pair</button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  <hr />
  <h2>Paired devices</h2>
  {#if trustedDevices.length === 0}
    <p><em>No paired devices yet.</em></p>
  {:else}
    <ul class="device-list">
      {#each trustedDevices as device (device.device_id)}
        <li>
          <div><strong>{device.display_name}</strong> ({device.os})</div>
          <button onclick={() => forget(device.device_id)}>Forget</button>
        </li>
      {/each}
    </ul>
  {/if}
</main>

{#if pairingRequest}
  <div class="modal-backdrop">
    <div class="modal">
      <h2>Pair with {pairingRequest.device_name}?</h2>
      <p>Confirm this code matches on both devices:</p>
      <p class="pin">{pairingRequest.pin.toString().padStart(6, "0")}</p>
      <div class="row">
        <button onclick={() => respondToPairing(true)}>Confirm match</button>
        <button onclick={() => respondToPairing(false)}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
.logo.vite:hover {
  filter: drop-shadow(0 0 2em #747bff);
}

.logo.svelte-kit:hover {
  filter: drop-shadow(0 0 2em #ff3e00);
}

:root {
  font-family: Inter, Avenir, Helvetica, Arial, sans-serif;
  font-size: 16px;
  line-height: 24px;
  font-weight: 400;

  color: #0f0f0f;
  background-color: #f6f6f6;

  font-synthesis: none;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  -webkit-text-size-adjust: 100%;
}

.container {
  margin: 0;
  padding-top: 10vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  text-align: center;
}

.logo {
  height: 6em;
  padding: 1.5em;
  will-change: filter;
  transition: 0.75s;
}

.logo.tauri:hover {
  filter: drop-shadow(0 0 2em #24c8db);
}

.row {
  display: flex;
  justify-content: center;
}

a {
  font-weight: 500;
  color: #646cff;
  text-decoration: inherit;
}

a:hover {
  color: #535bf2;
}

h1 {
  text-align: center;
}

input,
button {
  border-radius: 8px;
  border: 1px solid transparent;
  padding: 0.6em 1.2em;
  font-size: 1em;
  font-weight: 500;
  font-family: inherit;
  color: #0f0f0f;
  background-color: #ffffff;
  transition: border-color 0.25s;
  box-shadow: 0 2px 2px rgba(0, 0, 0, 0.2);
}

button {
  cursor: pointer;
}

button:hover {
  border-color: #396cd8;
}
button:active {
  border-color: #396cd8;
  background-color: #e8e8e8;
}

input,
button {
  outline: none;
}

#greet-input {
  margin-right: 5px;
}

.device-list {
  list-style: none;
  padding: 0;
  max-width: 480px;
  margin: 0 auto;
  text-align: left;
}

.device-list li {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1em;
  padding: 0.5em 0.8em;
  margin-bottom: 0.4em;
  background-color: rgba(127, 127, 127, 0.1);
  border-radius: 6px;
  text-align: left;
}

.badge {
  padding: 0.3em 0.7em;
  border-radius: 999px;
  background-color: rgba(52, 168, 83, 0.2);
  font-size: 0.85em;
  font-weight: 600;
  white-space: nowrap;
}

.status-message {
  max-width: 480px;
  margin: 0 auto;
}

.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.modal {
  background-color: #f6f6f6;
  color: #0f0f0f;
  border-radius: 12px;
  padding: 2em;
  max-width: 360px;
  text-align: center;
  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
}

.pin {
  font-size: 2.5em;
  font-weight: 700;
  letter-spacing: 0.15em;
  margin: 0.3em 0;
}

@media (prefers-color-scheme: dark) {
  :root {
    color: #f6f6f6;
    background-color: #2f2f2f;
  }

  a:hover {
    color: #24c8db;
  }

  input,
  button {
    color: #ffffff;
    background-color: #0f0f0f98;
  }
  button:active {
    background-color: #0f0f0f69;
  }

  .modal {
    background-color: #2f2f2f;
    color: #f6f6f6;
  }
}

</style>
