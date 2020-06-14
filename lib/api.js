let { getApi, getAndroidVersion } = require('./android');
try {
  getAndroidVersion();
} catch (e) {
  getApi = require('./jvm').getApi;
}
module.exports = getApi;
