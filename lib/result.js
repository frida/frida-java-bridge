const JNI_OK = 0;

function checkJniResult (name, result) {
  if (result !== JNI_OK) {
    throw new Error(name + ' failed: ' + result);
  }
}

module.exports = {
  checkJniResult: checkJniResult,
  JNI_OK: 0
};
