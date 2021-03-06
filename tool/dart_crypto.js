  // Add this below to the dart2js generated files if it requires 
  // random numbers. You can use similar to this below:
  // ```bash
  // for i in $(find ../benchmark/ -name \*.dart);
  // do
  //   B=$(basename $i .dart)
  //   O="$B.js"
  //   dart2js "$i" -o "$B.js"
  //   sed -i '' -e '/^(function dartProgram() {/r ../tool/dart_crypto.js' "$B.js"
  // done```
  // One-liner example
  // dart2js ../benchmark/all_benchmark.dart -o all_benchmark.js && sed -i '' -e '/^(function dartProgram() {/r dart_crypto.js' all_benchmark.js

  var self = typeof self !== 'undefined' ? self : Object.create(global);
  var crypto = typeof self !== 'undefined' ? (self.crypto || self.msCrypto) : null;

  var _randomBytes;

  if (!(crypto && crypto.getRandomValues) && typeof require !== 'undefined') {
    // Node.js.
    crypto = require('crypto');
    if (crypto && crypto.randomBytes) {
      _randomBytes = function (x, n) {
        var i, v = crypto.randomBytes(n);
        for (i = 0; i < n; i++) x[i] = v[i];
        for (i = 0; i < n; i++) v[i] = 0;
      };

      crypto.getRandomValues = function _randomValues(t) {
        _randomBytes(t, t.length);
      }
    }
  }

  self.crypto = typeof self.crypto !== 'undefined' ? self.crypto : crypto;
