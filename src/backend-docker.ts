// backend-docker: GP Relay поверх docker-контейнера (путь А).
// Контейнер = "VM": gp-relay (alpine + openconnect gp + dante socks5 + sshd).
// GUI-контракт тот же: connect/disconnect через ssh PTY в контейнер,
// socks ходит напрямую в контейнер (dante), а не через ssh -D.

import { invoke } from '@tauri-apps/api/core';

export interface DockerVpnSettings {
  containerName: string;
  imageName: string;
  socksPort: number;
  sshPort: number;
  portal: string;
  sshUser: string;
  identityFile?: string;
  knownHostsFile?: string;
}

export const DEFAULT_DOCKER_SETTINGS: DockerVpnSettings = {
  containerName: 'gp-relay',
  imageName: 'gp-relay:latest',
  socksPort: 1080,
  sshPort: 2222,
  portal: 'gp.domru.ru',
  sshUser: 'vpn',
};

/** docker inspect -f '{{.State.Running}}' — true/false/none */
export async function containerRunning(name: string): Promise<boolean> {
  try {
    const out = await invoke<string>('docker_exec', {
      args: ['inspect', '-f', '{{.State.Running}}', name],
    });
    return out.trim() === 'true';
  } catch {
    return false;
  }
}

/** Поднять контейнер, если не_running. Возвращает true, если стартовал сейчас. */
export async function ensureContainer(s: DockerVpnSettings): Promise<boolean> {
  if (await containerRunning(s.containerName)) return false;
  await invoke('docker_exec', {
    args: [
      'run', '-d',
      '--name', s.containerName,
      '--cap-add', 'NET_ADMIN',
      '--device', '/dev/net/tun',
      '-p', `${s.socksPort}:1080`,
      '-p', `${s.sshPort}:22`,
      '--restart', 'unless-stopped',
      s.imageName,
    ],
  });
  return true;
}

/** Убить контейнер (docker rm -f). */
export async function removeContainer(name: string): Promise<void> {
  await invoke('docker_exec', { args: ['rm', '-f', name] });
}

/** Живой ли SOCKS: коннект через прокси до произвольного хоста. */
export async function socksAlive(port: number): Promise<boolean> {
  try {
    const out = await invoke<string>('socks_probe', { port });
    return out === 'ok';
  } catch {
    return false;
  }
}
