import { getApi as androidGetApi, getAndroidVersion } from './android.js';
import { getApi as jvmGetApi } from './jvm.js';
let getApi = androidGetApi;
try {
  getAndroidVersion();
} catch (e) {
  getApi = jvmGetApi;
}
export default getApi;
