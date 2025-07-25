import { getApi as androidGetApi, getAndroidVersion } from './android.js';
import { getApi as jvmGetApi } from './jvm.js';

function detectEnvironment() {
  const platform = Process.platform;

  if (platform === 'windows') {
    return jvmGetApi;
  }

  if (platform === 'linux') {
    try {
      const modules = Process.enumerateModules();
      const hasAndroidRuntime = modules.some(m =>
        (m.name === 'libart.so' || m.name === 'libdvm.so') &&
        (m.path.includes('/system/') || m.path.includes('/apex/') || m.path.includes('/data/dalvik-cache'))
      );

      if (hasAndroidRuntime) {
        return androidGetApi;
      }
    } catch (e) {
    }
  }
  return jvmGetApi;
}

const getApi = detectEnvironment();
export default getApi;
